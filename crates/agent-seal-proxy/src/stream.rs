use axum::{
    body::Body,
    http::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use futures::{TryStreamExt, stream};

pub async fn stream_response(upstream_response: reqwest::Response) -> Response {
    let stream = upstream_response
        .bytes_stream()
        .map_err(|err| std::io::Error::other(err.to_string()));

    let stream = stream::try_unfold(
        (stream, String::new()),
        |(mut stream, mut carry)| async move {
            let chunk = match stream.try_next().await {
                Ok(Some(c)) => c,
                Ok(None) => {
                    if !carry.trim().is_empty() {
                        let mut out = String::new();
                        out.push_str(carry.trim_end_matches('\r'));
                        out.push('\n');
                        return Ok::<_, std::io::Error>(Some((
                            bytes::Bytes::from(out),
                            (stream, String::new()),
                        )));
                    }
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };

            let text = String::from_utf8_lossy(&chunk);
            carry.push_str(&text);

            if !carry.contains('\n') {
                return Ok(Some((bytes::Bytes::from(""), (stream, carry))));
            }

            let Some(last_newline) = carry.rfind('\n') else {
                return Ok(Some((bytes::Bytes::from(""), (stream, carry))));
            };

            let complete = carry[..=last_newline].to_string();
            carry = carry[last_newline + 1..].to_string();

            let mut out = String::new();
            for line in complete.lines() {
                if !line.trim().is_empty() {
                    out.push_str(line);
                    out.push('\n');
                }
            }

            Ok(Some((bytes::Bytes::from(out), (stream, carry))))
        },
    );

    (
        [
            (CONTENT_TYPE, "text/event-stream"),
            (CACHE_CONTROL, "no-cache"),
            (CONNECTION, "keep-alive"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::stream_response;

    async fn spawn_chunked_server(chunks: Vec<Vec<u8>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request_buf = [0_u8; 1024];
            let _ = socket.read(&mut request_buf).await;

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            for chunk in chunks {
                let header = format!("{:X}\r\n", chunk.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }

            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });

        format!("http://{addr}")
    }

    async fn stream_output(chunks: Vec<&str>) -> String {
        let base_url = spawn_chunked_server(
            chunks
                .into_iter()
                .map(|chunk| chunk.as_bytes().to_vec())
                .collect(),
        )
        .await;

        let upstream_response = reqwest::get(format!("{base_url}/stream")).await.unwrap();
        let response = stream_response(upstream_response).await;
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn stream_response_emits_complete_newline_terminated_lines() {
        let output = stream_output(vec!["data: one\n", "data: two\n"]).await;

        assert_eq!(output, "data: one\ndata: two\n");
    }

    #[tokio::test]
    async fn stream_response_carries_partial_lines_until_newline_arrives() {
        let output = stream_output(vec!["data: hel", "lo\n", "data: wo", "rld\n"]).await;

        assert_eq!(output, "data: hello\ndata: world\n");
    }

    #[tokio::test]
    async fn stream_response_filters_empty_and_whitespace_only_lines() {
        let output = stream_output(vec!["\n   \n", "data: kept\n", "\t\n\n"]).await;

        assert_eq!(output, "data: kept\n");
    }

    #[tokio::test]
    async fn stream_response_flushes_trailing_partial_line_on_stream_end() {
        let output = stream_output(vec!["data: trailing\r"]).await;

        assert_eq!(output, "data: trailing\n");
    }

    #[tokio::test]
    async fn stream_response_handles_empty_stream() {
        let output = stream_output(Vec::new()).await;

        assert!(output.is_empty());
    }
}
