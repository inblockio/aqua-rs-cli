// Define the HTML content as a constant
pub const SIGN_HTML: &str = r#"
<!DOCTYPE html>
<html>

<head>
    <title>Sign-In with Ethereum</title>
    <script src="https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js"></script>
    <style>
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            font-family: Arial, sans-serif;
        }

        .status {
            margin-top: 20px;
            padding: 10px;
            border-radius: 5px;
        }

        .error {
            background-color: #ffebee;
            color: #c62828;
        }

        .success {
            background-color: #e8f5e9;
            color: #2e7d32;
        }

        .message-box {
            margin-top: 20px;
            padding: 15px;
            background-color: #f5f5f5;
            border-radius: 5px;
            white-space: pre-wrap;
            font-family: monospace;
        }

        button {
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            background-color: #2196f3;
            color: white;
            border: none;
            border-radius: 5px;
        }

        button:hover {
            background-color: #1976d2;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Sign Aqua Chain With Metamask</h1>
        <button onclick="login()">Connect with MetaMask</button>
        <div id="status" class="status"></div>
        <div id="message" class="message-box"></div>
    </div>

    <script>
        function showStatus(message, isError = false) {
            const statusDiv = document.getElementById('status');
            statusDiv.className = `status ${isError ? 'error' : 'success'}`;
            statusDiv.textContent = message;
        }

        function showMessage(message) {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = message;
        }

        async function getSignMessage() {
            const response = await fetch('/message');
            if (!response.ok) {
                throw new Error('Failed to get sign message');
            }
            return response.json();
        }


        async function login() {
            if (typeof window.ethereum === 'undefined') {
                showStatus('Please install MetaMask!', true);
                return;
            }

            try {
                showStatus('Requesting account access...');

                // Request account access
                const accounts = await window.ethereum.request({
                    method: 'eth_requestAccounts'
                });
                const account = accounts[0];
                showStatus('Account connected: ' + account);

                // Get message to sign from server
                const { message } = await getSignMessage();
                showMessage(message);

                // Create a Web3Provider instance
                const provider = new window.ethers.providers.Web3Provider(window.ethereum);
                await provider.send("eth_requestAccounts", []); // Ensure connection
                const signer = provider.getSigner();

                showStatus('Please sign the message in MetaMask...');

                // Sign message
                const signature = await signer.signMessage(message);
                const publicKey = await signer.getAddress();

                showStatus('Message signed, sending to server...');

                console.log("Signature:", signature);
                console.log("Public Key:", publicKey);
                console.log("Wallet Address:", account);

                // Send to server
                const response = await fetch('/auth', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        signature: signature,
                        public_key: publicKey,
                        wallet_address: account
                    })
                });

                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }

                const result = await response.json();
                showStatus('Signing successful!, closing the tab in 2 seconds');

                setTimeout(() => {
                    window.close()
                }, 200);

            } catch (err) {
                console.error(err);
                showStatus('Failed to authenticate: ' + err.message, true);
            }
        }

        (async () => {
            // Get message to sign from server
            const { message } = await getSignMessage();
            showMessage(message);

            await login();

        })()
    </script>
</body>

</html>

"#;


pub const WITNESS_HTML: &str = r#"
<!DOCTYPE html>
<html>

<head>
    <title>Sign-In with Ethereum</title>
    <script src="https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js"></script>
    <style>
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            font-family: Arial, sans-serif;
        }

        .status {
            margin-top: 20px;
            padding: 10px;
            border-radius: 5px;
        }

        .error {
            background-color: #ffebee;
            color: #c62828;
        }

        .success {
            background-color: #e8f5e9;
            color: #2e7d32;
        }

        .message-box {
            margin-top: 20px;
            padding: 15px;
            background-color: #f5f5f5;
            border-radius: 5px;
            white-space: pre-wrap;
            font-family: monospace;
        }

        button {
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            background-color: #2196f3;
            color: white;
            border: none;
            border-radius: 5px;
        }

        button:hover {
            background-color: #1976d2;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Sign Aqua Chain With Metamask</h1>
        <button onclick="login()">Connect with MetaMask</button>
        <div id="status" class="status"></div>
        <div id="message" class="message-box"></div>
    </div>

    <script>

        function getChainId(key) {
            // Create a Map
            const map = new Map();
            // Add key-value pairs
            map.set('mainnet', '0x1');
            map.set('sepolia', '0xaa36a7');
            map.set('holesky', '0x4268');

            return map.get(key)
        }

        function getChainAddress(key) {
            // Create a Map
            const map = new Map();
            // Add key-value pairs
            map.set('mainnet', '0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611');
            map.set('sepolia', '0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611');
            map.set('holesky', '0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611');

            return map.get(key)
        }

        function showStatus(message, isError = false) {
            const statusDiv = document.getElementById('status');
            statusDiv.className = `status ${isError ? 'error' : 'success'}`;
            statusDiv.textContent = message;
        }

        function showMessage(message) {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = message;
        }

        async function getPreviousVerificationHash() {
            const response = await fetch('/message');
            if (!response.ok) {
                throw new Error('Failed to get previous verification  hash');
            }
            return response.json();
        }


        async function login() {
            if (typeof window.ethereum === 'undefined') {
                showStatus('Please install MetaMask!', true);
                return;
            }

            try {
                showStatus('Requesting account access...');

                // Request account access
                const accounts = await window.ethereum.request({
                    method: 'eth_requestAccounts'
                });
                const account = accounts[0];

                if (!account) {
                    alert("Please connect your wallet to continue");
                    return;
                }
                showStatus('Account connected: ' + account);

                // Get message to sign from server
                const { message } = await getPreviousVerificationHash();
                showMessage(message);

                // Create a Web3Provider instance
                const provider = new window.ethers.providers.Web3Provider(window.ethereum);
                await provider.send("eth_requestAccounts", []); // Ensure connection
                const signer = provider.getSigner();

                showStatus('Please sign the message in MetaMask...');

                // Sign message
                // const signature = await signer.signMessage(message);
                // const publicKey = await signer.getAddress();

                const contract_address = getChainAddress("sepolia");//ETH_CHAIN_ADDRESSES_MAP[appState.config.chain]
                const network = "sepolia";

                const params = [
                    {
                        from: account,
                        // to: SEPOLIA_SMART_CONTRACT_ADDRESS,
                        to: contract_address,
                        // gas and gasPrice are optional values which are
                        // automatically set by MetaMask.
                        // gas: '0x7cc0', // 30400
                        // gasPrice: '0x328400000',
                        data: '0x9cef4ea1' + witness_event_verification_hash,
                    },
                ]
                window.ethereum
                    .request({
                        method: 'eth_sendTransaction',
                        params: params,
                    })
                    .then( async (txhash) => {
                        console.log("Transaction hash is: ", txhash)
  
                            showStatus('Message signed, sending to server...');

                            console.log("tx_hash:", txhash);
                            console.log("wallet_address", ownerAddress);
                            console.log("network", network);

                            // Send to server
                            const response = await fetch('/auth', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({
                                    tx_hash: signature,
                                    wallet_address: ownerAddress,
                                    network: network
                                })
                            });

                            if (!response.ok) {
                                throw new Error(`Server responded with status: ${response.status}`);
                            }

                            const result = await response.json();
                            showStatus('Signing successful!, closing the tab in 2 seconds');

                            setTimeout(() => {
                                window.close()
                            }, 200);


                        }).catch((e ) => { alert("Something went wrong", e) })
              

            } catch (err) {
                console.error(err);
                showStatus('Failed to authenticate: ' + err.message, true);
            }
        }

        (async () => {
            // Get message to sign from server
            const { message } = await getPreviousVerificationHash();
            showMessage(message);

            await login();

        })()
    </script>
</body>

</html>
"#;