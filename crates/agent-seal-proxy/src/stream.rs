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
