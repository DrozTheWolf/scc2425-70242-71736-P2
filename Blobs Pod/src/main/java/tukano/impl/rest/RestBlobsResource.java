package tukano.impl.rest;

import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import tukano.api.Blobs;
import tukano.api.rest.RestBlobs;
import tukano.impl.JavaBlobs;

@Singleton
public class RestBlobsResource extends RestResource implements RestBlobs {

	final Blobs impl;
	
	public RestBlobsResource() {
		this.impl = JavaBlobs.getInstance();
	}

	/*
	@Override
	public void upload(Cookie cookie, String blobId, byte[] bytes, String token) {
		super.resultOrThrow( impl.upload(cookie, blobId, bytes, token));
	}*/

	@Override
	public void upload(String blobId, byte[] bytes, String token) {
		super.resultOrThrow( impl.upload(blobId, bytes, token));
	}

	/*
	@Override
	public byte[] download(Cookie cookie, String blobId, String token) {
		return super.resultOrThrow( impl.download( cookie, blobId, token ));
	}*/


	@Override
	public byte[] download(String blobId, String token) {
		return super.resultOrThrow( impl.download(blobId, token ));
	}

	/*
	@Override
	public void delete(Cookie cookie, String blobId, String token) {
		super.resultOrThrow( impl.delete( cookie, blobId, token ));
	}*/

	@Override
	public void delete(String blobId, String token) {
		super.resultOrThrow( impl.delete(blobId, token ));
	}
	
	@Override
	public void deleteAllBlobs(String userId, String password) {
		super.resultOrThrow( impl.deleteAllBlobs( userId, password ));
	}

	@Override
	public Response login(String user, String password) {
		return super.resultOrThrow( impl.login(user, password) );
	}
}
