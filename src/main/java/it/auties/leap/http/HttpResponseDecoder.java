package it.auties.leap.http;

import it.auties.leap.http.async.AsyncHttpResponseDecoder;
import it.auties.leap.http.blocking.BlockingHttpResponseDecoder;

public sealed interface HttpResponseDecoder permits AsyncHttpResponseDecoder, BlockingHttpResponseDecoder {
}
