import socket
import pathlib
import mimetypes
import sys


HOME_DIRECTORY = "webroot" # the home directory of this server


def response_ok(body=b"this is a pretty minimal response", mimetype=b"text/plain"):
    """
    Returns a basic HTTP response

    :param body - the body of the message
    :param mimetype - the mime-type of the message
    """

    # Construct the 200 OK response page.
    resp = []
    resp.append(b"HTTP/1.1 200 OK")
    resp.append("Content-Type: {0}".format(mimetype.decode('utf8')).encode('utf8'))
    resp.append(b"")
    resp.append(body)
    return b"\r\n".join(resp)


def response_method_not_allowed():
    """
    Returns a 405 Method Not Allowed response

    :param none
    """

    # Construct the 405 Method Not Allowed response page.
    resp = []
    resp.append("HTTP/1.1 405 Method Not Allowed")
    resp.append("")
    return "\r\n".join(resp).encode('utf8')


def response_not_found():
    """
    Returns a 404 Not Found response

    :param none
    """

    # Construct the 404 Not Found response page.
    resp = []
    resp.append("HTTP/1.1 404 Not Found")
    resp.append("")
    return "\r\n".join(resp).encode('utf8')


def parse_request(request):
    """
    Parses the request page and returns the URI of the resource page on the server.

    :param request: the request page sent by the client
    :return: the URI of the resource page on the server.
    """
    first_line = request.split("\r\n", 1)[0]
    method, uri, protocol = first_line.split()
    if method != "GET":
        raise NotImplementedError("We only accept GET")
    return uri


def resolve_uri(uri):
    """
    This method should return appropriate content and a mime type

    :param uri - the relative path of a file
    :return the content in the file and the mime-type of the file
    """

    # Create a PosixPath or WindowsPath of the given uri under webroot.
    path = pathlib.Path("{0}\{1}".format(HOME_DIRECTORY, uri))

    # Check to see whether or not the path refers to a file, a directory, or none.
    if path.is_file(): # a file

        # Find the mime-type of the file (e.g., text, html, x-python, jpeg or png).
        mime_type = mimetypes.guess_type(uri)[0].encode('utf8')
        # Read the bytes from the file.
        content = path.read_bytes()

        return content, mime_type

    elif path.is_dir(): # a directory
        content = ""
        for child in path.iterdir():
            content += "{0}\{1}\{2}".format(HOME_DIRECTORY, uri, child.name)

        return content.encode('utf8'), b"text/plain"

    else:  # does not exist
        raise NameError("The file does not exist.")


def server(log_buffer=sys.stderr):
    address = ('127.0.0.1', 10000)
    # Create a server socket with IPv4 and TCP.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Tell the kernel to reuse a local socket in TIME_WAIT state without waiting for its natural timeout to expire.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("making a server on {0}:{1}".format(*address), file=log_buffer)
    # Bind the server address with the server socket.
    sock.bind(address)
    # Listen for an attempted connection, and set the maximum number of connection requests that the socket will queue
    #  to be 1.
    sock.listen(1)

    try:
        while True:
            # Wait for a connection.
            print('waiting for a connection', file=log_buffer)
            conn, addr = sock.accept()  # blocking
            try:
                print('connection - {0}:{1}'.format(*addr), file=log_buffer)
                request = ''
                # Process the data received.  The server will process 1024 bytes of received data at a time, and
                # decode them as UTF-8.
                while True:
                    data = conn.recv(1024)
                    request += data.decode('utf8')
                    if len(data) < 1024:
                        break

                try:
                    # Parse the request page and return the URI of the resource page on the server.
                    uri = parse_request(request)
                except NotImplementedError:
                    # Return the 405 Method Not Allowed response page because the server only processes the GET
                    # request method.
                    response = response_method_not_allowed()
                else:
                    try:
                        # Look up the content of the URI of the resource page and the MIMI-type on the server.
                        content, mime_type = resolve_uri(uri)
                    except NameError:
                        # Return the 404 Not Found response because the resource page cannot be found on
                        # the server side.
                        response = response_not_found()

                    else:
                        # Return the 200 OK response page.
                        response = response_ok(content, mime_type)

                print('sending response', file=log_buffer)

                # Send the response back back to the client.
                conn.sendall(response)
            finally:
                # Close the client socket connection.
                conn.close()

    except KeyboardInterrupt:
        sock.close()
        return


if __name__ == '__main__':
    server()
    sys.exit(0)
