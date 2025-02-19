package it.auties.leap.http.response;

public final class HttpResponseStatusCode {
    // 1xx: Informational
    private static final int CONTINUE = 100;
    private static final int SWITCHING_PROTOCOLS = 101;
    private static final int PROCESSING = 102;
    private static final int EARLY_HINTS = 103;

    // 2xx: Successful
    private static final int OK = 200;
    private static final int CREATED = 201;
    private static final int ACCEPTED = 202;
    private static final int NON_AUTHORITATIVE_INFORMATION = 203;
    private static final int NO_CONTENT = 204;
    private static final int RESET_CONTENT = 205;
    private static final int PARTIAL_CONTENT = 206;
    private static final int MULTI_STATUS = 207;
    private static final int ALREADY_REPORTED = 208;
    private static final int IM_USED = 226;

    // 3xx: Redirection
    private static final int MULTIPLE_CHOICES = 300;
    private static final int MOVED_PERMANENTLY = 301;
    private static final int FOUND = 302;
    private static final int SEE_OTHER = 303;
    private static final int NOT_MODIFIED = 304;
    private static final int USE_PROXY = 305;
    // 306 is unused/reserved.
    private static final int TEMPORARY_REDIRECT = 307;
    private static final int PERMANENT_REDIRECT = 308;

    // 4xx: Client Error
    private static final int BAD_REQUEST = 400;
    private static final int UNAUTHORIZED = 401;
    private static final int PAYMENT_REQUIRED = 402;
    private static final int FORBIDDEN = 403;
    private static final int NOT_FOUND = 404;
    private static final int METHOD_NOT_ALLOWED = 405;
    private static final int NOT_ACCEPTABLE = 406;
    private static final int PROXY_AUTHENTICATION_REQUIRED = 407;
    private static final int REQUEST_TIMEOUT = 408;
    private static final int CONFLICT = 409;
    private static final int GONE = 410;
    private static final int LENGTH_REQUIRED = 411;
    private static final int PRECONDITION_FAILED = 412;
    private static final int PAYLOAD_TOO_LARGE = 413;
    private static final int URI_TOO_LONG = 414;
    private static final int UNSUPPORTED_MEDIA_TYPE = 415;
    private static final int RANGE_NOT_SATISFIABLE = 416;
    private static final int EXPECTATION_FAILED = 417;
    private static final int I_AM_A_TEAPOT = 418;
    private static final int MISDIRECTED_REQUEST = 421;
    private static final int UNPROCESSABLE_ENTITY = 422;
    private static final int LOCKED = 423;
    private static final int FAILED_DEPENDENCY = 424;
    private static final int TOO_EARLY = 425;
    private static final int UPGRADE_REQUIRED = 426;
    private static final int PRECONDITION_REQUIRED = 428;
    private static final int TOO_MANY_REQUESTS = 429;
    private static final int REQUEST_HEADER_FIELDS_TOO_LARGE = 431;
    private static final int UNAVAILABLE_FOR_LEGAL_REASONS = 451;

    // 5xx: Server Error
    private static final int INTERNAL_SERVER_ERROR = 500;
    private static final int NOT_IMPLEMENTED = 501;
    private static final int BAD_GATEWAY = 502;
    private static final int SERVICE_UNAVAILABLE = 503;
    private static final int GATEWAY_TIMEOUT = 504;
    private static final int HTTP_VERSION_NOT_SUPPORTED = 505;
    private static final int VARIANT_ALSO_NEGOTIATES = 506;
    private static final int INSUFFICIENT_STORAGE = 507;
    private static final int LOOP_DETECTED = 508;
    private static final int NOT_EXTENDED = 510;
    private static final int NETWORK_AUTHENTICATION_REQUIRED = 511;

    private HttpResponseStatusCode() {

    }

    public static int continueStatus() {
        return CONTINUE;
    }

    public static int switchingProtocols() {
        return SWITCHING_PROTOCOLS;
    }

    public static int processing() {
        return PROCESSING;
    }

    public static int earlyHints() {
        return EARLY_HINTS;
    }

    public static int ok() {
        return OK;
    }

    public static int created() {
        return CREATED;
    }

    public static int accepted() {
        return ACCEPTED;
    }

    public static int nonAuthoritativeInformation() {
        return NON_AUTHORITATIVE_INFORMATION;
    }

    public static int noContent() {
        return NO_CONTENT;
    }

    public static int resetContent() {
        return RESET_CONTENT;
    }

    public static int partialContent() {
        return PARTIAL_CONTENT;
    }

    public static int multiStatus() {
        return MULTI_STATUS;
    }

    public static int alreadyReported() {
        return ALREADY_REPORTED;
    }

    public static int imUsed() {
        return IM_USED;
    }

    public static int multipleChoices() {
        return MULTIPLE_CHOICES;
    }

    public static int movedPermanently() {
        return MOVED_PERMANENTLY;
    }

    public static int found() {
        return FOUND;
    }

    public static int seeOther() {
        return SEE_OTHER;
    }

    public static int notModified() {
        return NOT_MODIFIED;
    }

    public static int useProxy() {
        return USE_PROXY;
    }

    public static int temporaryRedirect() {
        return TEMPORARY_REDIRECT;
    }

    public static int permanentRedirect() {
        return PERMANENT_REDIRECT;
    }

    public static int badRequest() {
        return BAD_REQUEST;
    }

    public static int unauthorized() {
        return UNAUTHORIZED;
    }

    public static int paymentRequired() {
        return PAYMENT_REQUIRED;
    }

    public static int forbidden() {
        return FORBIDDEN;
    }

    public static int notFound() {
        return NOT_FOUND;
    }

    public static int methodNotAllowed() {
        return METHOD_NOT_ALLOWED;
    }

    public static int notAcceptable() {
        return NOT_ACCEPTABLE;
    }

    public static int proxyAuthenticationRequired() {
        return PROXY_AUTHENTICATION_REQUIRED;
    }

    public static int requestTimeout() {
        return REQUEST_TIMEOUT;
    }

    public static int conflict() {
        return CONFLICT;
    }

    public static int gone() {
        return GONE;
    }

    public static int lengthRequired() {
        return LENGTH_REQUIRED;
    }

    public static int preconditionFailed() {
        return PRECONDITION_FAILED;
    }

    public static int payloadTooLarge() {
        return PAYLOAD_TOO_LARGE;
    }

    public static int uriTooLong() {
        return URI_TOO_LONG;
    }

    public static int unsupportedMediaType() {
        return UNSUPPORTED_MEDIA_TYPE;
    }

    public static int rangeNotSatisfiable() {
        return RANGE_NOT_SATISFIABLE;
    }

    public static int expectationFailed() {
        return EXPECTATION_FAILED;
    }

    public static int iAmATeapot() {
        return I_AM_A_TEAPOT;
    }

    public static int misdirectedRequest() {
        return MISDIRECTED_REQUEST;
    }

    public static int unprocessableEntity() {
        return UNPROCESSABLE_ENTITY;
    }

    public static int locked() {
        return LOCKED;
    }

    public static int failedDependency() {
        return FAILED_DEPENDENCY;
    }

    public static int tooEarly() {
        return TOO_EARLY;
    }

    public static int upgradeRequired() {
        return UPGRADE_REQUIRED;
    }

    public static int preconditionRequired() {
        return PRECONDITION_REQUIRED;
    }

    public static int tooManyRequests() {
        return TOO_MANY_REQUESTS;
    }

    public static int requestHeaderFieldsTooLarge() {
        return REQUEST_HEADER_FIELDS_TOO_LARGE;
    }

    public static int unavailableForLegalReasons() {
        return UNAVAILABLE_FOR_LEGAL_REASONS;
    }

    public static int internalServerError() {
        return INTERNAL_SERVER_ERROR;
    }

    public static int notImplemented() {
        return NOT_IMPLEMENTED;
    }

    public static int badGateway() {
        return BAD_GATEWAY;
    }

    public static int serviceUnavailable() {
        return SERVICE_UNAVAILABLE;
    }

    public static int gatewayTimeout() {
        return GATEWAY_TIMEOUT;
    }

    public static int httpVersionNotSupported() {
        return HTTP_VERSION_NOT_SUPPORTED;
    }

    public static int variantAlsoNegotiates() {
        return VARIANT_ALSO_NEGOTIATES;
    }

    public static int insufficientStorage() {
        return INSUFFICIENT_STORAGE;
    }

    public static int loopDetected() {
        return LOOP_DETECTED;
    }

    public static int notExtended() {
        return NOT_EXTENDED;
    }

    public static int networkAuthenticationRequired() {
        return NETWORK_AUTHENTICATION_REQUIRED;
    }
}
