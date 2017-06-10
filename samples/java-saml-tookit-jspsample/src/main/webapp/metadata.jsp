<%@page import="java.util.*,com.onelogin.saml2.settings.*" language="java" contentType="application/xhtml+xml"%><%
Saml2Settings settings = new SettingsBuilder().fromFile("onelogin.saml.properties").build();
String metadata = settings.getSPMetadata();
List<String> errors = Saml2Settings.validateMetadata(metadata);
if (errors.isEmpty()) {
	out.println(metadata);
} else {
	response.setContentType("text/html; charset=UTF-8");

	for (String error : errors) {
	    out.println("<p>"+error+"</p>");
	}
}%>