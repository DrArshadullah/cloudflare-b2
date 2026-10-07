//
// Proxy private Backblaze S3-compatible API requests through Cloudflare,
// with signed CDN URLs and Cloudflare edge caching.
//
// Adapted from https://github.com/obezuk/worker-signed-s3-template
//

import { AwsClient } from 'aws4fetch'

const UNSIGNABLE_HEADERS = [
    'x-forwarded-proto',
    'x-real-ip',
    'accept-encoding',
    'if-match',
    'if-modified-since',
    'if-none-match',
    'if-range',
    'if-unmodified-since',
];

const HTTPS_PROTOCOL = "https:";
const HTTPS_PORT = "443";

const RANGE_RETRY_ATTEMPTS = 3;

function filterHeaders(headers, env) {
    return new Headers(Array.from(headers.entries())
        .filter(pair => !(
            UNSIGNABLE_HEADERS.includes(pair[0])
            || pair[0].startsWith('cf-')
            || ('ALLOWED_HEADERS' in env && !env['ALLOWED_HEADERS'].includes(pair[0]))
        ))
    );
}

function createHeadResponse(response) {
    return new Response(null, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText
    });
}

function isListBucketRequest(env, path) {
    const pathSegments = path.split('/');

    return (env['BUCKET_NAME'] === "$path" && pathSegments.length < 2)
        || (env['BUCKET_NAME'] !== "$path" && path.length === 0);
}

function toHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function createHmac(secret, message) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        {
            name: "HMAC",
            hash: "SHA-256"
        },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(message)
    );

    return toHex(signature);
}

async function verifyToken(secret, path, expires, disposition, filename, token) {
    if (!secret || !expires || !token) {
        return false;
    }

    const expiry = Number(expires);

    if (!Number.isSafeInteger(expiry)) {
        return false;
    }

    // Reject expired links, allowing 30 seconds of clock skew.
    if (expiry < Math.floor(Date.now() / 1000) - 30) {
        return false;
    }

    // Only allow the two modes we generate from BeDrive.
    if (disposition !== "inline" && disposition !== "attachment") {
        return false;
    }

    if (filename.includes("\r") || filename.includes("\n")) {
        return false;
    }

    const message = `${path}\n${expiry}\n${disposition}\n${filename}`;

    const expected = await createHmac(secret, message);

    if (expected.length !== token.length) {
        return false;
    }

    const expectedBytes = new TextEncoder().encode(expected);
    const suppliedBytes = new TextEncoder().encode(token);

    let difference = 0;

    for (let i = 0; i < expectedBytes.length; i++) {
        difference |= expectedBytes[i] ^ suppliedBytes[i];
    }

    return difference === 0;
}

function unauthorized() {
    return new Response("Unauthorized", {
        status: 403,
        headers: {
            "Cache-Control": "private, no-store"
        }
    });
}

function addDownloadHeaders(response, disposition, filename) {
    const newResponse = new Response(response.body, response);

    if (disposition === "attachment") {
        newResponse.headers.set(
            "Content-Disposition",
            `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`
        );
    } else {
        newResponse.headers.delete("Content-Disposition");
    }

    // Never allow the public Worker response itself to be cached.
    // The B2 fetch performed below is what Cloudflare caches.
    newResponse.headers.set(
        "Cache-Control",
        "private, no-store"
    );

    return newResponse;
}

// Suppress IntelliJ's "unused default export" warning
// noinspection JSUnusedGlobalSymbols
export default {
    async fetch(request, env) {

        // Only allow GET and HEAD methods.
        if (!['GET', 'HEAD'].includes(request.method)) {
            return new Response(null, {
                status: 405,
                statusText: "Method Not Allowed",
                headers: {
                    "Allow": "GET, HEAD",
                    "Cache-Control": "private, no-store"
                }
            });
        }

        const incomingUrl = new URL(request.url);

        //
        // ------------------------------------------------------------
        // 1. Validate the BeDrive-generated signed CDN URL
        // ------------------------------------------------------------
        //

        const expires = incomingUrl.searchParams.get("expires");
        const token = incomingUrl.searchParams.get("token");
        const disposition = incomingUrl.searchParams.get("disposition") || "inline";
        const filename = incomingUrl.searchParams.get("filename") || "";

        // The signature covers the exact public path.
        const requestedPath = incomingUrl.pathname;

        const validToken = await verifyToken(
            env["CDN_SHARED_SECRET"],
            requestedPath,
            expires,
            disposition,
            filename,
            token
        );

        if (!validToken) {
            return unauthorized();
        }

        //
        // ------------------------------------------------------------
        // 2. Build the existing Backblaze URL exactly as before
        // ------------------------------------------------------------
        //

        const url = new URL(request.url);

        // Incoming protocol and port are taken from the Worker environment.
        // B2 only supports HTTPS on 443.
        url.protocol = HTTPS_PROTOCOL;
        url.port = HTTPS_PORT;

        // Remove leading slashes from path.
        let path = url.pathname.replace(/^\//, '');

        // Remove trailing slashes.
        path = path.replace(/\/$/, '');

        // BeDrive's existing B2 object keys contain the endpoint as their
        // first path segment, so add it back internally.
        const b2EndpointPrefix = env['B2_ENDPOINT'] + '/';

        if (!path.startsWith(b2EndpointPrefix)) {
            path = b2EndpointPrefix + path;
        }

        // Use the reconstructed object key when requesting B2.
        url.pathname = '/' + path;

        // IMPORTANT:
        // Remove the CDN authentication parameters before contacting B2.
        // Therefore the token/expiry are NOT part of the B2 cache URL.
        url.search = "";

        //
        // ------------------------------------------------------------
        // 3. Reject bucket listing
        // ------------------------------------------------------------
        //

        if (isListBucketRequest(env, path) && String(env['ALLOW_LIST_BUCKET']) !== "true") {
            return new Response(null, {
                status: 404,
                statusText: "Not Found",
                headers: {
                    "Cache-Control": "private, no-store"
                }
            });
        }

        //
        // ------------------------------------------------------------
        // 4. Configure B2 origin
        // ------------------------------------------------------------
        //

        const rcloneDownload = String(env["RCLONE_DOWNLOAD"]) === 'true';

        switch (env['BUCKET_NAME']) {
            case "$path":
                url.hostname = env['B2_ENDPOINT'];
                break;

            case "$host":
                url.hostname = url.hostname.split('.')[0] + '.' + env['B2_ENDPOINT'];
                break;

            default:
                url.hostname = env['BUCKET_NAME'] + "." + env['B2_ENDPOINT'];
                break;
        }

        const headers = filterHeaders(request.headers, env);

        //
        // ------------------------------------------------------------
        // 5. Sign the B2 request
        // ------------------------------------------------------------
        //

        const client = new AwsClient({
            "accessKeyId": env['B2_APPLICATION_KEY_ID'],
            "secretAccessKey": env['B2_APPLICATION_KEY'],
            "service": "s3",
        });

        const requestMethod = request.method;

        if (rcloneDownload) {
            if (env['BUCKET_NAME'] === "$path") {
                url.pathname = path.replace(/^file\//, "");
            } else {
                url.pathname = path.replace(/^file\/[^/]+\//, "");
            }
        }

        // Preserve the existing behaviour where HEAD is signed as GET.
        const signedRequest = await client.sign(url.toString(), {
            method: 'GET',
            headers: headers
        });

        //
        // ------------------------------------------------------------
        // 6. Fetch B2 through Cloudflare's cache
        // ------------------------------------------------------------
        //

        async function fetchFromB2() {
            return fetch(signedRequest, {
                cf: {
                    cacheEverything: true,
                    cacheTtlByStatus: {
                        "200-299": 86400,
                        "404": 60,
                        "500-599": 0
                    }
                }
            });
        }

        //
        // Range requests
        //
        // Keep the existing retry protection. Cloudflare's cache can
        // subsequently handle cached range delivery.
        //

        if (signedRequest.headers.has("range")) {

            let attempts = RANGE_RETRY_ATTEMPTS;
            let response;

            do {
                const controller = new AbortController();

                response = await fetch(signedRequest, {
                    cf: {
                        cacheEverything: true,
                        cacheTtlByStatus: {
                            "200-299": 86400,
                            "404": 60,
                            "500-599": 0
                        }
                    },
                    signal: controller.signal,
                });

                if (response.headers.has("content-range")) {

                    if (attempts < RANGE_RETRY_ATTEMPTS) {
                        console.log(
                            `Retry for ${signedRequest.url} succeeded - response has content-range header`
                        );
                    }

                    break;

                } else if (response.ok) {

                    attempts -= 1;

                    console.error(
                        `Range header in request for ${signedRequest.url} but no content-range header in response. Will retry ${attempts} more times`
                    );

                    if (attempts > 0) {
                        controller.abort();
                    }

                } else {

                    break;
                }

            } while (attempts > 0);

            if (attempts <= 0) {
                console.error(
                    `Tried range request for ${signedRequest.url} ${RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`
                );
            }

            if (requestMethod === 'HEAD') {
                const headResponse = createHeadResponse(response);

                return addDownloadHeaders(
                    headResponse,
                    disposition,
                    filename
                );
            }

            return addDownloadHeaders(
                response,
                disposition,
                filename
            );
        }

        //
        // Normal GET / HEAD
        //

        const response = await fetchFromB2();

        if (requestMethod === 'HEAD') {
            const headResponse = createHeadResponse(response);

            return addDownloadHeaders(
                headResponse,
                disposition,
                filename
            );
        }

        return addDownloadHeaders(
            response,
            disposition,
            filename
        );
    },
};
