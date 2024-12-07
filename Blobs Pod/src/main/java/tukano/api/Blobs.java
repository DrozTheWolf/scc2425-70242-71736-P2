package tukano.api;

import jakarta.ws.rs.core.Cookie;
import tukano.api.Result;

import java.util.function.Consumer;

import jakarta.ws.rs.core.Response;

/**
 * Interface of blob service for storing short videos media ...
 */
public interface Blobs {
	String NAME = "blobs";


	Result<Void> upload(Cookie cookie, String blobId, byte[] bytes, String token);
	// Result<Void> upload(String blobId, byte[] bytes, String token);


	Result<byte[]> download(Cookie cookie, String blobId, String token);
	// Result<byte[]> download(String blobId, String token);


	/**
	 * Downloads a short video blob resource as a result suitable for streaming
	 * large-sized byte resources 
	 * 
	 * The default implementation just sinks a single chunk of bytes taken from download(blobId)
	 * 
	 * @param blobId the id of the blob
	 * @param sink - the consumer of the chunks of data
	 * @return (OK,), if the blob exists;
	 *		   NOT_FOUND, if no blob matches the provided blobId
	 */
	default Result<Void> downloadToSink(String blobId, Consumer<byte[]> sink, String token) {
		var res = download(blobId, token);
		if (!res.isOK())
			return Result.error(res.error());

		sink.accept(res.value());
		return Result.ok();
	}
	
	Result<Void> delete( Cookie cookie, String blobId, String token );
	// Result<Void> delete(String blobId, String token );
	
	Result<Void> deleteAllBlobs( String userId, String token );

	Result<Response> login( String user, String password );
}
