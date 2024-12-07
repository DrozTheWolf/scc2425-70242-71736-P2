package tukano.impl;

import static java.lang.String.format;
import static tukano.api.Result.error;
import static tukano.api.Result.ErrorCode.FORBIDDEN;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.logging.Logger;

import javax.ws.rs.WebApplicationException;


import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import tukano.impl.auth.RequestCookies;

import tukano.api.Blobs;
import tukano.api.Result;
import tukano.impl.rest.TukanoRestServer;
import tukano.impl.storage.BlobStorage;
import tukano.impl.storage.FilesystemStorage;
import tukano.impl.FakeRedisLayer;
import tukano.impl.Session;
import utils.Hash;
import utils.Hex;

public class JavaBlobs implements Blobs {

	static final boolean useAuth = true;

	static final String PATH = "login";
	static final String USER = "username";
	static final String PWD = "password";
	static final String COOKIE_KEY = "scc:session";
	static final String LOGIN_PAGE = "login.html";
	private static final int MAX_COOKIE_AGE = 3600;
	static final String REDIRECT_TO_AFTER_LOGIN = "/ctrl/version";

	static final String ADMIN_USER = "admin";
	static final String ADMIN_PASS = "admin";

	private static Blobs instance;
	private static Logger Log = Logger.getLogger(JavaBlobs.class.getName());

	public String baseURI;
	private BlobStorage storage;
	
	synchronized public static Blobs getInstance() {
		if( instance == null )
			instance = new JavaBlobs();
		return instance;
	}
	
	private JavaBlobs() {
		storage = new FilesystemStorage();
		baseURI = String.format("%s/%s/", TukanoRestServer.blobURI, Blobs.NAME);
	}

	/*
	@Override
	public Result<Void> upload(String blobId, byte[] bytes, String token) {
		Log.info(() -> format("upload : blobId = %s, sha256 = %s, token = %s\n", blobId, Hex.of(Hash.sha256(bytes)), token));

		if (!validBlobId(blobId, token))
			return error(FORBIDDEN);

		return storage.write( toPath( blobId ), bytes);
	}*/

	@Override
    	public Result<Void> upload(Cookie cookie, String blobId, byte[] bytes, String token) {
    		Log.info(() -> format("upload : blobId = %s, sha256 = %s, token = %s\n", blobId, Hex.of(Hash.sha256(bytes)), token));

    		if (!validBlobId(blobId, token))
    			return error(FORBIDDEN);

    		return storage.write( toPath( blobId ), bytes);
    	}

    /*
	@Override
	public Result<byte[]> download(String blobId, String token) {
		Log.info(() -> format("download : blobId = %s, token=%s\n", blobId, token));

		if( ! validBlobId( blobId, token ) )
			return error(FORBIDDEN);

		return storage.read( toPath( blobId ) );
	}*/

	@Override
    	public Result<byte[]> download(Cookie cookie, String blobId, String token) {
    		Log.info(() -> format("download : blobId = %s, token=%s\n", blobId, token));

    		if( ! validBlobId( blobId, token ) )
    			return error(FORBIDDEN);

    		return storage.read( toPath( blobId ) );
    	}

	@Override
	public Result<Void> downloadToSink(String blobId, Consumer<byte[]> sink, String token) {
		Log.info(() -> format("downloadToSink : blobId = %s, token = %s\n", blobId, token));

		if( ! validBlobId( blobId, token ) )
			return error(FORBIDDEN);

		return storage.read( toPath(blobId), sink);
	}

    /*
	@Override
	public Result<Void> delete(String blobId, String token) {
		Log.info(() -> format("delete : blobId = %s, token=%s\n", blobId, token));
	
		if( ! validBlobId( blobId, token ) )
			return error(FORBIDDEN);

		return storage.delete( toPath(blobId));
	}*/

	@Override
    	public Result<Void> delete(Cookie cookie, String blobId, String token) {
    		Log.info(() -> format("delete : blobId = %s, token=%s\n", blobId, token));

    		if( ! validBlobId( blobId, token ) )
    			return error(FORBIDDEN);

    		return storage.delete( toPath(blobId));
    	}

	@Override
	public Result<Response> login( String user, String password ) {
		Log.info(() -> format("login : user = %s, passwordn=%s\n", user, password));


		if (user.equals(ADMIN_USER) && password.equals(ADMIN_PASS)){
			Log.info(() -> format("login: auth as admin"));

			String uid = UUID.randomUUID().toString();
			var cookie = new NewCookie.Builder(COOKIE_KEY)
                            .value(uid)
                            .path("/")
                            .comment("adminid")
                            .maxAge(MAX_COOKIE_AGE)
                            .secure(false)
                            .httpOnly(true)
                            .build();

            FakeRedisLayer.getInstance().putSession(new Session(uid, user, true)); // admin
            return Result.ok(Response.ok().cookie(cookie).build());
		}

		boolean pwdOk = checkUserPass(user, password);
		if (pwdOk) {
			String uid = UUID.randomUUID().toString();
			var cookie = new NewCookie.Builder(COOKIE_KEY)
					.value(uid).path("/")
					.comment("sessionid")
					.maxAge(MAX_COOKIE_AGE)
					.secure(false) //ideally it should be true to only work for https requests
					.httpOnly(true)
					.build();
			
			FakeRedisLayer.getInstance().putSession( new Session( uid, user, false)); // non-admin
            return Result.ok(Response.ok().cookie(cookie).build());
		} else {
			throw new NotAuthorizedException("Incorrect login");
            return Result.error(FORBIDDEN);
		}

	}
	
	@Override
	public Result<Void> deleteAllBlobs(String userId, String token) {
		Log.info(() -> format("deleteAllBlobs : userId = %s, token=%s\n", userId, token));

		if( ! Token.isValid( token, userId ) )
			return error(FORBIDDEN);
		
		return storage.delete( toPath(userId));
	}

	static public Session validateSession(String userId) throws NotAuthorizedException {
    		var cookies = RequestCookies.get();
    		return validateSession( cookies.get(COOKIE_KEY ), userId );
    	}

    	static public Session validateSession(Cookie cookie, String userId) throws NotAuthorizedException {

    		if (cookie == null )
    			throw new NotAuthorizedException("No session initialized");

    		var session = FakeRedisLayer.getInstance().getSession( cookie.getValue());
    		if( session == null )
    			throw new NotAuthorizedException("No valid session initialized");

    		if (session.user() == null || session.user().length() == 0)
    			throw new NotAuthorizedException("No valid session initialized");

    		if (!session.user().equals(userId))
    			throw new NotAuthorizedException("Invalid user : " + session.user());

    		return session;
    	}
	
	private boolean validBlobId(String blobId, String token) {		
		System.out.println( toURL(blobId));
		return Token.isValid(token, toURL(blobId));
	}

	private String toPath(String blobId) {
		return blobId.replace("+", "/");
	}
	
	private String toURL( String blobId ) {
		return baseURI + blobId ;
	}

	private boolean checkUserPass(String userId, String password){
		try {
			        // IP/tukano-1/rest /users /userid?pwd=X
        			String url = String.format("%s/users/%s?pwd=%s", TukanoRestServer.usersShortsURI, userId, password);
        			HttpClient client = HttpClient.newHttpClient();

        			HttpRequest request = HttpRequest.newBuilder()
        					.uri(URI.create(url))
        					.GET()
        					.build();

        			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        			return response.statusCode() == 200 || response.statusCode() == 204;

        		} catch (Exception e) {
        			e.printStackTrace();
        			System.out.println("Error occurred while sending DELETE request: " + e.getMessage());
        			return false;
        		}
	}
}