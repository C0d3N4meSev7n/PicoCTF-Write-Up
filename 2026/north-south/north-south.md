# North-South-PicoCTF-2026

---

### Web exploitation - Medium - (Config file)

---

#### Description:

#### I've set up geo-based routing - can you outsmart it?

#### You're trying to retrieve the flag, but there's a catch: access to the real service is restricted based on your geographic location. Only requests from a specific region are routed to the server that holds the flag. Everyone else is sent somewhere... less interesting.

---

- Based on the challenge description, it seems like I have to fake IP or something to be able to access the server that contains the flag. Because if not coming from “that” specific region, I only see this, it's just like this and nothing more.
    
    ![image.png](images/image.png)
    
- Opening the given config file, because it’s kinda short, it’s easier for me to notice just 2 things:
    - The module being used: `ngx_http_geoip2_module`
    - The If block of the route `/`
    
    ```
    load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;
    
    worker_processes 1;
    events { worker_connections 1024; }
    
    http {
        include       mime.types;
        default_type  application/octet-stream;
    
        geoip2 /etc/nginx/GeoLite2-Country.mmdb {
            auto_reload 5m;
            $geoip2_data_country_code default=ZZ country iso_code;
        }
    
        upstream north {
            server 127.0.0.1:8000;
        }
    
        upstream south {
            server 127.0.0.1:9000;
        }
    
        server {
            listen 80;
    
            location / {
                if ($geoip2_data_country_code = IS) {
                    proxy_pass http://south;
                }
    
                proxy_pass http://north;
            }
        }
    }
    
    ```
    
- After doing some research, here what I know so far about the module `ngx_http_geoip2_module` :
    - This is an NGINX module (a native web server module rather than application-level code like Node or PHP) designed to look up a client's country based on their connecting IP address using the MaxMind GeoLite2 database. (`.mmdb` is a binary format optimized for fast IP range lookups).
    - In these lines:
        
        ```
        geoip2 /etc/nginx/GeoLite2-Country.mmdb {
                auto_reload 5m;
                $geoip2_data_country_code default=ZZ country iso_code;
            }
        ```
        
    - `auto_reload 5m` : Automatically reload the `.mmdb` file every 5 minutes (in case the database is updated).
    - `$geoip2_data_country_code default=ZZ country iso_code` : Define an NGINX variable named $geoip2_data_country_code that retrieves its value from the country.iso_code field in the database (US, VN, IS,…). If the IP cannot be looked up (not found in the database), assign the default code ZZ (the "unknown" code per MaxMind convention).
    - By default, this module uses `$remote_addr` , meaning it takes the actual IP address of the TCP connection to NGINX, not the value obtained from an HTTP header like `X-Forwarded-For`, so I won’t try using that header in this challenge.
- Turning to the if block, it’s simple, if my IP comes from IS, I’ll be routed to the server that holds the flag.
    
    ```
    location / {
                if ($geoip2_data_country_code = IS) {
                    proxy_pass http://south;
                }
    
                proxy_pass http://north;
            }
    ```
    
- With everything gathered, I need a way to route my traffic through an Icelandic IP address. The easiest way to do that is using `tor` .
- By adding these 2 lines (192,193) at the bottom of the `/etc/tor/torrc` file, I’ve configured `tor` to only use relays bearing the Icelandic national flag as exit nodes and also force it to use that specific exit node. (If set to 0, Tor will automatically fall back to another node if Iceland is unavailable).
    
    ![image.png](images/image%201.png)
    
- Then restart the `tor` service.
    
    ![image.png](images/image%202.png)
    
- Finally, run the command `curl --socks5-hostname 127.0.0.1:9050 http://lonely-island.picoctf.net:[PORT]/` to route all the traffics through `tor`before it gets to the application, and I got the flag.
    
    ![image.png](images/image%203.png)
    
- Root cause:
    - Access restriction based purely on client source IP geolocation, with no
    additional authentication/authorization layer, anyone whose real connection
    originates from (or is routed through) an Icelandic IP satisfies the check
    completely, regardless of who they actually are.
    - No header spoofing possible: since the config has no real_ip_module
    configured, NGINX evaluates $remote_addr (the actual TCP source), making
    this specifically a "genuinely relocate your traffic" problem rather than a
    "trick the server into misreading a header" problem.
    - Geolocation is an environmental signal, not an identity credential:
    MaxMind's GeoLite2 lookup only proves which network block a packet's source
    IP belongs to at the time of the request, not who controls that connection.
    Any routing layer that can place traffic inside that IP range - a VPN exit,
    a proxy, or in this case a Tor relay pinned via ExitNodes - satisfies the
    check just as validly as a real resident would, because the check was never
    actually verifying identity or authorization, only network origin.
- Takeaway: geofencing is a routing decision, not an access control, it's
appropriate for content licensing or regional load balancing, but using it as
the sole gate in front of sensitive data conflates "where the packet came from"
with "who is allowed to see this."
