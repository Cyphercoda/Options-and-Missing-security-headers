import burp.*;
import java.util.ArrayList;
import java.util.List;

public class BurpExtension implements IBurpExtension, IHttpListener {

  private IExtensionHelpers helpers;

  @Override
  public void registerExtensionCallbacks(IBurpExtensionCallbacks callbacks) {
    // Set the extension helpers
    helpers = callbacks.getHelpers();
    // Register this extension as an HTTP listener
    callbacks.registerHttpListener(this);
  }

  @Override
  public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    // Check if the message is a response
    if (!messageIsRequest) {
      IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());

      // Check if the response has a status code of 200
      if (responseInfo.getStatusCode() == 200) {
        // Check if the OPTIONS method is enabled
        if (isOptionsMethodEnabled(messageInfo.getRequest())) {
          callbacks.printError("OPTIONS method is enabled!");
        }

        // Check for missing security headers
        List<String> missingHeaders = getMissingSecurityHeaders(responseInfo.getHeaders());
        if (!missingHeaders.isEmpty()) {
          callbacks.printError("Missing security headers: " + String.join(", ", missingHeaders));
        }
      }
    }
  }

  private boolean isOptionsMethodEnabled(byte[] request) {
    IRequestInfo requestInfo = helpers.analyzeRequest(request);
    return requestInfo.getMethod().equals("OPTIONS");
  }

  private List<String> getMissingSecurityHeaders(List<String> headers) {
    List<String> missingHeaders = new ArrayList<>();

    if (!headersContains("X-XSS-Protection", headers)) {
      missingHeaders.add("X-XSS-Protection");
    }

    if (!headersContains("X-Content-Type-Options", headers)) {
      missingHeaders.add("X-Content-Type-Options");
    }

    if (!headersContains("X-Frame-Options", headers)) {
      missingHeaders.add("X-Frame-Options");
    }

    return missingHeaders;
  }

  private boolean headersContains(String header, List<String> headers) {
    for (String h : headers) {
      if (h.startsWith(header)) {
        return true;
      }
    }

    return false;
  }
}
