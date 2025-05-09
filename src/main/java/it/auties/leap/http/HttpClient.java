package it.auties.leap.http;

import it.auties.leap.http.async.AsyncHttpClient;
import it.auties.leap.http.blocking.BlockingHttpClient;

public sealed interface HttpClient extends AutoCloseable permits AsyncHttpClient, BlockingHttpClient {
}
