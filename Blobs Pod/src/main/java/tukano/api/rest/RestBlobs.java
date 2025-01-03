package tukano.api.rest;


import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import tukano.impl.JavaBlobs;

@Path(RestBlobs.PATH)
public interface RestBlobs {
	
	String PATH = "/blobs";
	String BLOB_ID = "blobId";
	String TOKEN = "token";
	String BLOBS = "blobs";
	String USER_ID = "userId";
	String PWD = "pwd";
	String LOGIN = "login";

	/*
 	@POST
 	@Path("/{" + BLOB_ID +"}")
 	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	void upload(@CookieParam(JavaBlobs.COOKIE_KEY) Cookie cookie, @PathParam(BLOB_ID) String blobId, byte[] bytes, @QueryParam(TOKEN) String token);
	*/

 	@POST
 	@Path("/{" + BLOB_ID +"}")
 	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	void upload(@PathParam(BLOB_ID) String blobId, byte[] bytes, @QueryParam(TOKEN) String token);

	/*
 	@GET
 	@Path("/{" + BLOB_ID +"}") 	
 	@Produces(MediaType.APPLICATION_OCTET_STREAM)
 	byte[] download(@CookieParam(JavaBlobs.COOKIE_KEY) Cookie cookie, @PathParam(BLOB_ID) String blobId, @QueryParam(TOKEN) String token);
	*/


 	@GET
    @Path("/{" + BLOB_ID +"}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    byte[] download(@PathParam(BLOB_ID) String blobId, @QueryParam(TOKEN) String token);

	 /*
	@DELETE
	@Path("/{" + BLOB_ID + "}")
	void delete(@CookieParam(JavaBlobs.COOKIE_KEY) Cookie cookie, @PathParam(BLOB_ID) String blobId, @QueryParam(TOKEN) String token );
	*/

    @DELETE
	@Path("/{" + BLOB_ID + "}")
	void delete(@PathParam(BLOB_ID) String blobId, @QueryParam(TOKEN) String token );


	@DELETE
	@Path("/{" + USER_ID + "}/" + BLOBS)
	void deleteAllBlobs(@PathParam(USER_ID) String userId, @QueryParam(TOKEN) String token );

	@POST
	@Path("/{" + USER_ID + "}/" + LOGIN)
	Response login(@PathParam(USER_ID) String userId, @QueryParam(PWD) String password);
}
