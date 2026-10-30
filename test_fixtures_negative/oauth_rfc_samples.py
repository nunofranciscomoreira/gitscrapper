def prepare_headers():
    """Builds an OAuth 1 Authorization header (RFC 5849, section 3.5.1)::

        Authorization: OAuth realm="Example",
            oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            oauth_timestamp="137131200",
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_version="1.0"
    """


def sign():
    """Signature examples from RFC 5849, sections 1.2 and 3.1::

            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"

            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"
    """


def parse_token_response():
    """Token responses from RFC 6749, sections 4.2.2 and 5.1::

        HTTP/1.1 302 Found
        Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
                &state=xyz&token_type=example&expires_in=3600

        {
          "access_token":"2YotnFZFEjr1zCsicMWpAA",
          "token_type":"example",
          "expires_in":3600,
          "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
        }

    and their use (RFC 6750, section 2.1)::

        GET /resource/1 HTTP/1.1
        Host: example.com
        Authorization: Bearer mF_9.B5f-4.1JqM
    """
