# aksasas


XSS Scanner Made with 0ranos Fingers sweat

## Setup

### Step 1: Configure `mitmproxy`

1. **Start `mitmproxy`**:

    ```bash
    python aksasas.py
    ```

    - The script will listen on port `8088` by default. Ensure this port is free or change it to another port if necessary.

2. **Configure Your Browser or Application to Use `mitmproxy`**:

    - Set your browser or application to use `mitmproxy` as the proxy. You can configure the proxy settings to point to `127.0.0.1:8088` (or the port you've set in the script).

### Step 2: Whitelist Hosts

When you run the script, you will be prompted to enter the hostnames you want to whitelist for testing (e.g., `potato.com,tomato.org,orange.biz`). The script will only test requests to your i hosts.

### Step 3: Generate and Install the `mitmproxy` Certificate (Optional but Recommended)

For full SSL interception:

1. **Generate a certificate**:

https://docs.mitmproxy.org/stable/concepts-certificates/

2. **Install the certificate** in your browser:
   - Follow the instructions provided by `mitmproxy` to install the certificate, enabling the tool to intercept and decrypt HTTPS traffic.

### Step 4: Monitor and Review Results

1. **Run the tool** by starting your browser and navigating to the sites you wish to test.
2. **Check the console output**:
   - Any potential reflections will be reported in the console with details of the affected URL, parameter, and injected payload.
   - Connection errors will also be reported, indicating which domains may not be reachable.
  
[![Demo](https://raw.githubusercontent.com/oran0s/aksasas/main/demo.gif)]
