package it.auties.leap.http;

import it.auties.leap.http.async.AsyncHttpRequestEncoder;
import it.auties.leap.http.blocking.BlockingHttpRequestEncoder;

public sealed interface HttpRequestEncoder permits AsyncHttpRequestEncoder, BlockingHttpRequestEncoder {
}
