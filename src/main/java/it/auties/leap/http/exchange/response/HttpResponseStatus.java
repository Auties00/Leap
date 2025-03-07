package it.auties.leap.http.exchange.response;

import java.util.*;

public final class HttpResponseStatus {
    // 1xx: Informational
    private static final HttpResponseStatus CONTINUE = new HttpResponseStatus(100, "Continue");
    private static final HttpResponseStatus SWITCHING_PROTOCOLS = new HttpResponseStatus(101, "Switching Protocols");
    private static final HttpResponseStatus PROCESSING = new HttpResponseStatus(102, "Processing");
    private static final HttpResponseStatus EARLY_HINTS = new HttpResponseStatus(103, "Early Hints");

    // 2xx: Successful
    private static final HttpResponseStatus OK = new HttpResponseStatus(200, "OK");
    private static final HttpResponseStatus CREATED = new HttpResponseStatus(201, "Created");
    private static final HttpResponseStatus ACCEPTED = new HttpResponseStatus(202, "Accepted");
    private static final HttpResponseStatus NON_AUTHORITATIVE_INFORMATION = new HttpResponseStatus(203, "Non-Authoritative Information");
    private static final HttpResponseStatus NO_CONTENT = new HttpResponseStatus(204, "No Content");
    private static final HttpResponseStatus RESET_CONTENT = new HttpResponseStatus(205, "Reset Content");
    private static final HttpResponseStatus PARTIAL_CONTENT = new HttpResponseStatus(206, "Partial Content");
    private static final HttpResponseStatus MULTI_STATUS = new HttpResponseStatus(207, "Multi-Status");
    private static final HttpResponseStatus ALREADY_REPORTED = new HttpResponseStatus(208, "Already Reported");
    private static final HttpResponseStatus IM_USED = new HttpResponseStatus(226, "IM Used");

    // 3xx: Redirection
    private static final HttpResponseStatus MULTIPLE_CHOICES = new HttpResponseStatus(300, "Multiple Choices");
    private static final HttpResponseStatus MOVED_PERMANENTLY = new HttpResponseStatus(301, "Moved Permanently");
    private static final HttpResponseStatus FOUND = new HttpResponseStatus(302, "Found");
    private static final HttpResponseStatus SEE_OTHER = new HttpResponseStatus(303, "See Other");
    private static final HttpResponseStatus NOT_MODIFIED = new HttpResponseStatus(304, "Not Modified");
    private static final HttpResponseStatus USE_PROXY = new HttpResponseStatus(305, "Use Proxy");
    // 306 is unused/reserved.
    private static final HttpResponseStatus TEMPORARY_REDIRECT = new HttpResponseStatus(307, "Temporary Redirect");
    private static final HttpResponseStatus PERMANENT_REDIRECT = new HttpResponseStatus(308, "Permanent Redirect");

    // 4xx: Client Error
    private static final HttpResponseStatus BAD_REQUEST = new HttpResponseStatus(400, "Bad Request");
    private static final HttpResponseStatus UNAUTHORIZED = new HttpResponseStatus(401, "Unauthorized");
    private static final HttpResponseStatus PAYMENT_REQUIRED = new HttpResponseStatus(402, "Payment Required");
    private static final HttpResponseStatus FORBIDDEN = new HttpResponseStatus(403, "Forbidden");
    private static final HttpResponseStatus NOT_FOUND = new HttpResponseStatus(404, "Not Found");
    private static final HttpResponseStatus METHOD_NOT_ALLOWED = new HttpResponseStatus(405, "Method Not Allowed");
    private static final HttpResponseStatus NOT_ACCEPTABLE = new HttpResponseStatus(406, "Not Acceptable");
    private static final HttpResponseStatus PROXY_AUTHENTICATION_REQUIRED = new HttpResponseStatus(407, "Proxy Authentication Required");
    private static final HttpResponseStatus REQUEST_TIMEOUT = new HttpResponseStatus(408, "Request Timeout");
    private static final HttpResponseStatus CONFLICT = new HttpResponseStatus(409, "Conflict");
    private static final HttpResponseStatus GONE = new HttpResponseStatus(410, "Gone");
    private static final HttpResponseStatus LENGTH_REQUIRED = new HttpResponseStatus(411, "Length Required");
    private static final HttpResponseStatus PRECONDITION_FAILED = new HttpResponseStatus(412, "Precondition Failed");
    private static final HttpResponseStatus PAYLOAD_TOO_LARGE = new HttpResponseStatus(413, "Payload Too Large");
    private static final HttpResponseStatus URI_TOO_LONG = new HttpResponseStatus(414, "URI Too Long");
    private static final HttpResponseStatus UNSUPPORTED_MEDIA_TYPE = new HttpResponseStatus(415, "Unsupported Media Type");
    private static final HttpResponseStatus RANGE_NOT_SATISFIABLE = new HttpResponseStatus(416, "Range Not Satisfiable");
    private static final HttpResponseStatus EXPECTATION_FAILED = new HttpResponseStatus(417, "Expectation Failed");
    private static final HttpResponseStatus I_AM_A_TEAPOT = new HttpResponseStatus(418, "I'm a teapot");
    private static final HttpResponseStatus MISDIRECTED_REQUEST = new HttpResponseStatus(421, "Misdirected Request");
    private static final HttpResponseStatus UNPROCESSABLE_ENTITY = new HttpResponseStatus(422, "Unprocessable Entity");
    private static final HttpResponseStatus LOCKED = new HttpResponseStatus(423, "Locked");
    private static final HttpResponseStatus FAILED_DEPENDENCY = new HttpResponseStatus(424, "Failed Dependency");
    private static final HttpResponseStatus TOO_EARLY = new HttpResponseStatus(425, "Too Early");
    private static final HttpResponseStatus UPGRADE_REQUIRED = new HttpResponseStatus(426, "Upgrade Required");
    private static final HttpResponseStatus PRECONDITION_REQUIRED = new HttpResponseStatus(428, "Precondition Required");
    private static final HttpResponseStatus TOO_MANY_REQUESTS = new HttpResponseStatus(429, "Too Many Requests");
    private static final HttpResponseStatus REQUEST_HEADER_FIELDS_TOO_LARGE = new HttpResponseStatus(431, "Request Header Fields Too Large");
    private static final HttpResponseStatus UNAVAILABLE_FOR_LEGAL_REASONS = new HttpResponseStatus(451, "Unavailable For Legal Reasons");

    // 5xx: Server Error
    private static final HttpResponseStatus INTERNAL_SERVER_ERROR = new HttpResponseStatus(500, "Internal Server Error");
    private static final HttpResponseStatus NOT_IMPLEMENTED = new HttpResponseStatus(501, "Not Implemented");
    private static final HttpResponseStatus BAD_GATEWAY = new HttpResponseStatus(502, "Bad Gateway");
    private static final HttpResponseStatus SERVICE_UNAVAILABLE = new HttpResponseStatus(503, "Service Unavailable");
    private static final HttpResponseStatus GATEWAY_TIMEOUT = new HttpResponseStatus(504, "Gateway Timeout");
    private static final HttpResponseStatus HTTP_VERSION_NOT_SUPPORTED = new HttpResponseStatus(505, "HTTP Version Not Supported");
    private static final HttpResponseStatus VARIANT_ALSO_NEGOTIATES = new HttpResponseStatus(506, "Variant Also Negotiates");
    private static final HttpResponseStatus INSUFFICIENT_STORAGE = new HttpResponseStatus(507, "Insufficient Storage");
    private static final HttpResponseStatus LOOP_DETECTED = new HttpResponseStatus(508, "Loop Detected");
    private static final HttpResponseStatus NOT_EXTENDED = new HttpResponseStatus(510, "Not Extended");
    private static final HttpResponseStatus NETWORK_AUTHENTICATION_REQUIRED = new HttpResponseStatus(511, "Network Authentication Required");

    // Maps for lookup by status code and reason phrase
    private static final Map<Integer, HttpResponseStatus> CODE_TO_STATUS = new HashMap<>();
    private static final Map<String, HttpResponseStatus> PHRASE_TO_STATUS = new HashMap<>();

    static {
        addStatus(CONTINUE);
        addStatus(SWITCHING_PROTOCOLS);
        addStatus(PROCESSING);
        addStatus(EARLY_HINTS);

        addStatus(OK);
        addStatus(CREATED);
        addStatus(ACCEPTED);
        addStatus(NON_AUTHORITATIVE_INFORMATION);
        addStatus(NO_CONTENT);
        addStatus(RESET_CONTENT);
        addStatus(PARTIAL_CONTENT);
        addStatus(MULTI_STATUS);
        addStatus(ALREADY_REPORTED);
        addStatus(IM_USED);

        addStatus(MULTIPLE_CHOICES);
        addStatus(MOVED_PERMANENTLY);
        addStatus(FOUND);
        addStatus(SEE_OTHER);
        addStatus(NOT_MODIFIED);
        addStatus(USE_PROXY);
        addStatus(TEMPORARY_REDIRECT);
        addStatus(PERMANENT_REDIRECT);

        addStatus(BAD_REQUEST);
        addStatus(UNAUTHORIZED);
        addStatus(PAYMENT_REQUIRED);
        addStatus(FORBIDDEN);
        addStatus(NOT_FOUND);
        addStatus(METHOD_NOT_ALLOWED);
        addStatus(NOT_ACCEPTABLE);
        addStatus(PROXY_AUTHENTICATION_REQUIRED);
        addStatus(REQUEST_TIMEOUT);
        addStatus(CONFLICT);
        addStatus(GONE);
        addStatus(LENGTH_REQUIRED);
        addStatus(PRECONDITION_FAILED);
        addStatus(PAYLOAD_TOO_LARGE);
        addStatus(URI_TOO_LONG);
        addStatus(UNSUPPORTED_MEDIA_TYPE);
        addStatus(RANGE_NOT_SATISFIABLE);
        addStatus(EXPECTATION_FAILED);
        addStatus(I_AM_A_TEAPOT);
        addStatus(MISDIRECTED_REQUEST);
        addStatus(UNPROCESSABLE_ENTITY);
        addStatus(LOCKED);
        addStatus(FAILED_DEPENDENCY);
        addStatus(TOO_EARLY);
        addStatus(UPGRADE_REQUIRED);
        addStatus(PRECONDITION_REQUIRED);
        addStatus(TOO_MANY_REQUESTS);
        addStatus(REQUEST_HEADER_FIELDS_TOO_LARGE);
        addStatus(UNAVAILABLE_FOR_LEGAL_REASONS);

        addStatus(INTERNAL_SERVER_ERROR);
        addStatus(NOT_IMPLEMENTED);
        addStatus(BAD_GATEWAY);
        addStatus(SERVICE_UNAVAILABLE);
        addStatus(GATEWAY_TIMEOUT);
        addStatus(HTTP_VERSION_NOT_SUPPORTED);
        addStatus(VARIANT_ALSO_NEGOTIATES);
        addStatus(INSUFFICIENT_STORAGE);
        addStatus(LOOP_DETECTED);
        addStatus(NOT_EXTENDED);
        addStatus(NETWORK_AUTHENTICATION_REQUIRED);
    }

    private static void addStatus(HttpResponseStatus status) {
        CODE_TO_STATUS.put(status.statusCode(), status);
        PHRASE_TO_STATUS.put(status.reasonPhrase().orElseThrow().toLowerCase(Locale.ROOT), status);
    }

    private final int statusCode;
    private final String reasonPhrase;

    private HttpResponseStatus(int statusCode, String reasonPhrase) {
        this.statusCode = statusCode;
        this.reasonPhrase = reasonPhrase;
    }

    public static HttpResponseStatus of(int statusCode) {
        var result = CODE_TO_STATUS.get(statusCode);
        if(result != null) {
            return result;
        }

        return new HttpResponseStatus(statusCode, null);
    }

    public static Optional<HttpResponseStatus> of(String reasonPhrase) {
        if (reasonPhrase == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(PHRASE_TO_STATUS.get(reasonPhrase.toLowerCase()));
    }

    public static HttpResponseStatus continueStatus() {
        return CONTINUE;
    }

    public static HttpResponseStatus switchingProtocols() {
        return SWITCHING_PROTOCOLS;
    }

    public static HttpResponseStatus processing() {
        return PROCESSING;
    }

    public static HttpResponseStatus earlyHints() {
        return EARLY_HINTS;
    }

    public static HttpResponseStatus ok() {
        return OK;
    }

    public static HttpResponseStatus created() {
        return CREATED;
    }

    public static HttpResponseStatus accepted() {
        return ACCEPTED;
    }

    public static HttpResponseStatus nonAuthoritativeInformation() {
        return NON_AUTHORITATIVE_INFORMATION;
    }

    public static HttpResponseStatus noContent() {
        return NO_CONTENT;
    }

    public static HttpResponseStatus resetContent() {
        return RESET_CONTENT;
    }

    public static HttpResponseStatus partialContent() {
        return PARTIAL_CONTENT;
    }

    public static HttpResponseStatus multiStatus() {
        return MULTI_STATUS;
    }

    public static HttpResponseStatus alreadyReported() {
        return ALREADY_REPORTED;
    }

    public static HttpResponseStatus imUsed() {
        return IM_USED;
    }

    public static HttpResponseStatus multipleChoices() {
        return MULTIPLE_CHOICES;
    }

    public static HttpResponseStatus movedPermanently() {
        return MOVED_PERMANENTLY;
    }

    public static HttpResponseStatus found() {
        return FOUND;
    }

    public static HttpResponseStatus seeOther() {
        return SEE_OTHER;
    }

    public static HttpResponseStatus notModified() {
        return NOT_MODIFIED;
    }

    public static HttpResponseStatus useProxy() {
        return USE_PROXY;
    }

    public static HttpResponseStatus temporaryRedirect() {
        return TEMPORARY_REDIRECT;
    }

    public static HttpResponseStatus permanentRedirect() {
        return PERMANENT_REDIRECT;
    }

    public static HttpResponseStatus badRequest() {
        return BAD_REQUEST;
    }

    public static HttpResponseStatus unauthorized() {
        return UNAUTHORIZED;
    }

    public static HttpResponseStatus paymentRequired() {
        return PAYMENT_REQUIRED;
    }

    public static HttpResponseStatus forbidden() {
        return FORBIDDEN;
    }

    public static HttpResponseStatus notFound() {
        return NOT_FOUND;
    }

    public static HttpResponseStatus methodNotAllowed() {
        return METHOD_NOT_ALLOWED;
    }

    public static HttpResponseStatus notAcceptable() {
        return NOT_ACCEPTABLE;
    }

    public static HttpResponseStatus proxyAuthenticationRequired() {
        return PROXY_AUTHENTICATION_REQUIRED;
    }

    public static HttpResponseStatus requestTimeout() {
        return REQUEST_TIMEOUT;
    }

    public static HttpResponseStatus conflict() {
        return CONFLICT;
    }

    public static HttpResponseStatus gone() {
        return GONE;
    }

    public static HttpResponseStatus lengthRequired() {
        return LENGTH_REQUIRED;
    }

    public static HttpResponseStatus preconditionFailed() {
        return PRECONDITION_FAILED;
    }

    public static HttpResponseStatus payloadTooLarge() {
        return PAYLOAD_TOO_LARGE;
    }

    public static HttpResponseStatus uriTooLong() {
        return URI_TOO_LONG;
    }

    public static HttpResponseStatus unsupportedMediaType() {
        return UNSUPPORTED_MEDIA_TYPE;
    }

    public static HttpResponseStatus rangeNotSatisfiable() {
        return RANGE_NOT_SATISFIABLE;
    }

    public static HttpResponseStatus expectationFailed() {
        return EXPECTATION_FAILED;
    }

    public static HttpResponseStatus iAmATeapot() {
        return I_AM_A_TEAPOT;
    }

    public static HttpResponseStatus misdirectedRequest() {
        return MISDIRECTED_REQUEST;
    }

    public static HttpResponseStatus unprocessableEntity() {
        return UNPROCESSABLE_ENTITY;
    }

    public static HttpResponseStatus locked() {
        return LOCKED;
    }

    public static HttpResponseStatus failedDependency() {
        return FAILED_DEPENDENCY;
    }

    public static HttpResponseStatus tooEarly() {
        return TOO_EARLY;
    }

    public static HttpResponseStatus upgradeRequired() {
        return UPGRADE_REQUIRED;
    }

    public static HttpResponseStatus preconditionRequired() {
        return PRECONDITION_REQUIRED;
    }

    public static HttpResponseStatus tooManyRequests() {
        return TOO_MANY_REQUESTS;
    }

    public static HttpResponseStatus requestHeaderFieldsTooLarge() {
        return REQUEST_HEADER_FIELDS_TOO_LARGE;
    }

    public static HttpResponseStatus unavailableForLegalReasons() {
        return UNAVAILABLE_FOR_LEGAL_REASONS;
    }

    public static HttpResponseStatus internalServerError() {
        return INTERNAL_SERVER_ERROR;
    }

    public static HttpResponseStatus notImplemented() {
        return NOT_IMPLEMENTED;
    }

    public static HttpResponseStatus badGateway() {
        return BAD_GATEWAY;
    }

    public static HttpResponseStatus serviceUnavailable() {
        return SERVICE_UNAVAILABLE;
    }

    public static HttpResponseStatus gatewayTimeout() {
        return GATEWAY_TIMEOUT;
    }

    public static HttpResponseStatus httpVersionNotSupported() {
        return HTTP_VERSION_NOT_SUPPORTED;
    }

    public static HttpResponseStatus variantAlsoNegotiates() {
        return VARIANT_ALSO_NEGOTIATES;
    }

    public static HttpResponseStatus insufficientStorage() {
        return INSUFFICIENT_STORAGE;
    }

    public static HttpResponseStatus loopDetected() {
        return LOOP_DETECTED;
    }

    public static HttpResponseStatus notExtended() {
        return NOT_EXTENDED;
    }

    public static HttpResponseStatus networkAuthenticationRequired() {
        return NETWORK_AUTHENTICATION_REQUIRED;
    }

    public int statusCode() {
        return statusCode;
    }

    public Optional<String> reasonPhrase() {
        return Optional.ofNullable(reasonPhrase);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof HttpResponseStatus that
                && statusCode == that.statusCode
                && Objects.equals(reasonPhrase, that.reasonPhrase);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statusCode, reasonPhrase);
    }

    @Override
    public String toString() {
        return "HttpResponseStatus[" +
                "statusCode=" + statusCode + ", " +
                "reasonPhrase=" + reasonPhrase + ']';
    }
}
