<html>
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Aviator Crash Game</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" />
  <script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
  <script src="https://cdn.socket.io/4.6.1/socket.io.min.js"></script>
  <script src="https://unpkg.com/react-router-dom@6/umd/react-router-dom.production.min.js"></script>
  <style>
    body {
      font-family: 'Inter', sans-serif;
      background-color: #111827;
      color: white;
      margin: 0;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      padding: 1rem;
    }
    a {
      color: inherit;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div id="root" class="w-full max-w-md"></div>

  <script type="text/javascript">
    const {
      useState,
      useEffect,
      useRef,
      createElement: e,
      Fragment,
    } = React;
    const {
      BrowserRouter,
      Routes,
      Route,
      Link,
      Navigate,
      useNavigate,
    } = ReactRouterDOM;

    async function sha256(message) {
      const msgBuffer = new TextEncoder().encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    async function hmacSha256(key, message) {
      const enc = new TextEncoder();
      const keyData = enc.encode(key);
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
      const sigArray = Array.from(new Uint8Array(sig));
      return sigArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    function ProvablyFairVerification() {
      const [serverSeed, setServerSeed] = useState('');
      const [clientSeed, setClientSeed] = useState('');
      const [expectedHash, setExpectedHash] = useState('');
      const [calculatedHash, setCalculatedHash] = useState('');
      const [hmac, setHmac] = useState('');
      const [multiplier, setMultiplier] = useState(null);

      async function verify() {
        const hash = await sha256(serverSeed);
        setCalculatedHash(hash);
        if (hash !== expectedHash) {
          alert('Server seed hash does not match expected hash');
          return;
        }
        const hmacVal = await hmacSha256(serverSeed, clientSeed);
        setHmac(hmacVal);
        const hmacSlice = hmacVal.slice(0, 13);
        const intVal = parseInt(hmacSlice, 16);
        const maxVal = Math.pow(2, 52);
        if (intVal >= maxVal) {
          setMultiplier(1);
          return;
        }
        const result = Math.floor((99 / (1 - intVal / maxVal))) / 100;
        setMultiplier(result < 1 ? 1 : result);
      }

      return e("div", { className: "bg-gray-800 p-4 rounded max-w-md mx-auto my-4 text-white" },
        e("h3", { className: "text-xl font-bold mb-2" }, "Provably Fair Verification"),
        e("label", { className: "block mb-1" }, "Server Seed (hex):"),
        e("input", {
          type: "text",
          className: "w-full p-2 mb-2 rounded text-black",
          value: serverSeed,
          onChange: e => setServerSeed(e.target.value)
        }),
        e("label", { className: "block mb-1" }, "Expected Server Seed Hash (hex):"),
        e("input", {
          type: "text",
          className: "w-full p-2 mb-2 rounded text-black",
          value: expectedHash,
          onChange: e => setExpectedHash(e.target.value)
        }),
        e("label", { className: "block mb-1" }, "Client Seed (hex):"),
        e("input", {
          type: "text",
          className: "w-full p-2 mb-2 rounded text-black",
          value: clientSeed,
          onChange: e => setClientSeed(e.target.value)
        }),
        e("button", {
          onClick: verify,
          className: "bg-blue-600 px-4 py-2 rounded hover:bg-blue-700"
        }, "Verify"),
        calculatedHash && e("p", { className: "mt-2" },
          "Calculated Server Seed Hash: ",
          e("code", null, calculatedHash)
        ),
        hmac && e("p", null,
          "HMAC-SHA256: ",
          e("code", null, hmac)
        ),
        multiplier !== null && e("p", null,
          "Calculated Crash Multiplier: ",
          e("strong", null, multiplier.toFixed(2) + "x")
        )
      );
    }

    function Wallet({ token, onBalanceChange }) {
      const [depositAmount, setDepositAmount] = useState('');
      const [withdrawAmount, setWithdrawAmount] = useState('');
      const [message, setMessage] = useState('');

      async function deposit() {
        const amount = parseFloat(depositAmount);
        if (isNaN(amount) || amount <= 0) {
          setMessage('Invalid deposit amount');
          return;
        }
        try {
          const res = await axios.post(
            '/api/game/deposit',
            { amount },
            { headers: { Authorization: `Bearer ${token}` } }
          );
          setMessage(`Deposit initiated. TxID: ${res.data.txId}`);
          setDepositAmount('');
          onBalanceChange(await fetchBalance());
        } catch {
          setMessage('Deposit failed');
        }
      }

      async function withdraw() {
        const amount = parseFloat(withdrawAmount);
        if (isNaN(amount) || amount <= 0) {
          setMessage('Invalid withdraw amount');
          return;
        }
        try {
          const res = await axios.post(
            '/api/game/withdraw',
            { amount },
            { headers: { Authorization: `Bearer ${token}` } }
          );
          setMessage(`Withdraw initiated. TxID: ${res.data.txId}`);
          setWithdrawAmount('');
          onBalanceChange(await fetchBalance());
        } catch {
          setMessage('Withdraw failed');
        }
      }

      async function fetchBalance() {
        try {
          const res = await axios.get('/api/game/wallet', {
            headers: { Authorization: `Bearer ${token}` },
          });
          return res.data.walletBalance;
        } catch {
          return 0;
        }
      }

      return e("div", { className: "bg-gray-800 p-4 rounded mb-4" },
        e("h3", { className: "text-lg font-semibold mb-2" }, "Wallet"),
        e("div", { className: "flex space-x-2 mb-2" },
          e("input", {
            type: "number",
            min: "0.01",
            step: "0.01",
            placeholder: "Deposit amount",
            className: "p-2 rounded text-black flex-1",
            value: depositAmount,
            onChange: e => setDepositAmount(e.target.value)
          }),
          e("button", {
            onClick: deposit,
            className: "bg-green-600 px-4 py-2 rounded hover:bg-green-700"
          }, "Deposit")
        ),
        e("div", { className: "flex space-x-2 mb-2" },
          e("input", {
            type: "number",
            min: "0.01",
            step: "0.01",
            placeholder: "Withdraw amount",
            className: "p-2 rounded text-black flex-1",
            value: withdrawAmount,
            onChange: e => setWithdrawAmount(e.target.value)
          }),
          e("button", {
            onClick: withdraw,
            className: "bg-red-600 px-4 py-2 rounded hover:bg-red-700"
          }, "Withdraw")
        ),
        message && e("p", { className: "text-sm text-yellow-400" }, message)
      );
    }

    function KYC({ token }) {
      const [file, setFile] = useState(null);
      const [status, setStatus] = useState('unknown');
      const [message, setMessage] = useState('');

      useEffect(() => {
        fetchStatus();
      }, []);

      async function fetchStatus() {
        try {
          const res = await axios.get('/api/kyc/status', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setStatus(res.data.kycStatus);
        } catch {
          setStatus('unknown');
        }
      }

      async function upload() {
        if (!file) {
          setMessage('Please select a file');
          return;
        }
        const formData = new FormData();
        formData.append('idDocument', file);
        try {
          await axios.post('/api/kyc/upload_id', formData, {
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'multipart/form-data',
            },
          });
          setMessage('ID uploaded, verification pending');
          fetchStatus();
        } catch {
          setMessage('Upload failed');
        }
      }

      return e("div", { className: "bg-gray-800 p-4 rounded mb-4 max-w-md mx-auto text-white" },
        e("h3", { className: "text-lg font-semibold mb-2" }, "KYC Verification"),
        e("p", null, "Status: ", e("strong", null, status)),
        e("input", {
          type: "file",
          accept: "image/*,application/pdf",
          onChange: e => setFile(e.target.files ? e.target.files[0] : null),
          className: "my-2 text-black"
        }),
        e("button", {
          onClick: upload,
          className: "bg-blue-600 px-4 py-2 rounded hover:bg-blue-700"
        }, "Upload ID Document"),
        message && e("p", { className: "mt-2 text-yellow-400" }, message)
      );
    }

    function AdminPanel({ token }) {
      const [logs, setLogs] = useState([]);
      const [action, setAction] = useState('');
      const [message, setMessage] = useState('');
      const [loading, setLoading] = useState(false);

      useEffect(() => {
        fetchLogs();
      }, []);

      async function fetchLogs() {
        try {
          const res = await axios.get('/api/admin/logs', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setLogs(res.data);
        } catch {
          setMessage('Failed to fetch logs');
        }
      }

      async function logAction() {
        if (!action.trim()) {
          setMessage('Action cannot be empty');
          return;
        }
        setLoading(true);
        try {
          await axios.post(
            '/api/admin/log_action',
            { action },
            { headers: { Authorization: `Bearer ${token}` } }
          );
          setMessage('Action logged');
          setAction('');
          fetchLogs();
        } catch {
          setMessage('Failed to log action');
        } finally {
          setLoading(false);
        }
      }

      return e("div", { className: "bg-gray-800 p-4 rounded max-w-4xl mx-auto my-4 text-white" },
        e("h3", { className: "text-xl font-bold mb-4" }, "Admin Panel"),
        e("div", { className: "mb-4" },
          e("textarea", {
            rows: 3,
            className: "w-full p-2 rounded text-black",
            placeholder: "Enter admin action description",
            value: action,
            onChange: e => setAction(e.target.value),
            disabled: loading
          }),
          e("button", {
            onClick: logAction,
            disabled: loading,
            className: "mt-2 bg-blue-600 px-4 py-2 rounded hover:bg-blue-700 disabled:opacity-50"
          }, "Log Action"),
          message && e("p", { className: "mt-2 text-yellow-400" }, message)
        ),
        e("h4", { className: "text-lg font-semibold mb-2" }, "Recent Admin Logs"),
        e("div", { className: "overflow-auto max-h-96 border border-gray-700 rounded" },
          e("table", { className: "w-full text-sm text-left" },
            e("thead", { className: "bg-gray-700 sticky top-0" },
              e("tr", null,
                e("th", { className: "px-2 py-1" }, "Timestamp"),
                e("th", { className: "px-2 py-1" }, "Admin ID"),
                e("th", { className: "px-2 py-1" }, "Action"),
                e("th", { className: "px-2 py-1" }, "IP"),
                e("th", { className: "px-2 py-1" }, "Signature")
              )
            ),
            e("tbody", null,
              logs.map(log =>
                e("tr", { key: log._id, className: "border-b border-gray-700" },
                  e("td", { className: "px-2 py-1" }, new Date(log.timestamp).toLocaleString()),
                  e("td", { className: "px-2 py-1" }, log.adminId),
                  e("td", { className: "px-2 py-1 break-words max-w-xs" }, log.action),
                  e("td", { className: "px-2 py-1" }, log.ip),
                  e("td", { className: "px-2 py-1 break-words max-w-xs" }, log.signature)
                )
              )
            )
          )
        )
      );
    }

    function PromoteSelf({ token, onPromoted }) {
      const [loading, setLoading] = useState(false);
      const [message, setMessage] = useState('');

      async function promote() {
        setLoading(true);
        setMessage('');
        try {
          const res = await axios.post(
            '/api/admin/promote_self',
            {},
            { headers: { Authorization: `Bearer ${token}` } }
          );
          if (res.data.success) {
            setMessage('You are now an admin!');
            onPromoted();
          } else {
            setMessage('Promotion failed');
          }
        } catch {
          setMessage('Promotion failed');
        } finally {
          setLoading(false);
        }
      }

      return e("div", { className: "bg-yellow-700 p-4 rounded mb-4 max-w-md mx-auto text-white text-center" },
        e("p", { className: "mb-2 font-semibold" }, "You are not an admin yet."),
        e("button", {
          onClick: promote,
          disabled: loading,
          className: "bg-yellow-500 px-4 py-2 rounded hover:bg-yellow-600 disabled:opacity-50"
        }, loading ? "Promoting..." : "Promote Me to Admin"),
        message && e("p", { className: "mt-2" }, message)
      );
    }

    function Register({ onRegistered }) {
      const [username, setUsername] = useState('');
      const [email, setEmail] = useState('');
      const [password, setPassword] = useState('');
      const [message, setMessage] = useState('');

      async function register() {
        if (!username || !email || !password) {
          setMessage('Please fill all fields');
          return;
        }
        try {
          await axios.post('/api/auth/register', { username, email, password });
          setMessage('Registration successful! Please login.');
          onRegistered();
        } catch (e) {
          setMessage(e.response?.data?.error || 'Registration failed');
        }
      }

      return e("div", { className: "min-h-screen flex flex-col items-center justify-center bg-gray-900 text-white p-4" },
        e("h1", { className: "text-3xl font-bold mb-6" }, "Register"),
        e("input", {
          type: "text",
          placeholder: "Username",
          className: "mb-2 p-2 rounded text-black w-64",
          value: username,
          onChange: e => setUsername(e.target.value)
        }),
        e("input", {
          type: "email",
          placeholder: "Email",
          className: "mb-2 p-2 rounded text-black w-64",
          value: email,
          onChange: e => setEmail(e.target.value)
        }),
        e("input", {
          type: "password",
          placeholder: "Password",
          className: "mb-4 p-2 rounded text-black w-64",
          value: password,
          onChange: e => setPassword(e.target.value)
        }),
        e("button", {
          onClick: register,
          className: "bg-green-600 px-6 py-2 rounded hover:bg-green-700 transition"
        }, "Register"),
        message && e("p", { className: "mt-4 text-yellow-400" }, message)
      );
    }

    function App() {
      const [token, setToken] = useState(null);
      const [username, setUsername] = useState('');
      const [password, setPassword] = useState('');
      const [userRole, setUserRole] = useState(null);
      const [adminPromoted, setAdminPromoted] = useState(false);
      const [loginError, setLoginError] = useState('');
      const [showRegister, setShowRegister] = useState(false);
      const [socket, setSocket] = useState(null);
      const [roundId, setRoundId] = useState('');
      const [serverSeedHash, setServerSeedHash] = useState('');
      const [betCloseIn, setBetCloseIn] = useState(0);
      const [multiplier, setMultiplier] = useState(1);
      const [crashMultiplier, setCrashMultiplier] = useState(null);
      const [betAmount, setBetAmount] = useState(0);
      const [betPlaced, setBetPlaced] = useState(false);
      const [cashedOut, setCashedOut] = useState(false);
      const [walletBalance, setWalletBalance] = useState(0);
      const [messages, setMessages] = useState([]);

      const multiplierRef = useRef(multiplier);
      multiplierRef.current = multiplier;

      useEffect(() => {
        if (token) {
          const s = io(window.location.origin, {
            auth: { token },
          });
          setSocket(s);

          s.on('connect_error', (err) => {
            addMessage(`Socket error: ${err.message}`);
          });

          s.on('round_start', (data) => {
            setRoundId(data.roundId);
            setServerSeedHash(data.serverSeedHash);
            setBetCloseIn(data.bet_close_in);
            setMultiplier(1);
            setCrashMultiplier(null);
            setBetPlaced(false);
            setCashedOut(false);
            addMessage(`Round started: ${data.roundId}`);
          });

          s.on('multiplier_update', (data) => {
            setMultiplier(data.multiplier);
          });

          s.on('round_crash', (data) => {
            setCrashMultiplier(data.crashMultiplier);
            addMessage(`Round crashed at ${data.crashMultiplier}x`);
          });

          s.on('payouts', (data) => {
            addMessage(`Payouts processed for round ${data.roundId}`);
            refreshWallet();
          });

          s.on('error', (data) => {
            addMessage(`Error: ${data.message}`);
          });

          refreshWallet();

          return () => {
            s.disconnect();
          };
        }
      }, [token]);

      async function refreshWallet() {
        if (!token) return;
        try {
          const res = await axios.get('/api/game/wallet', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setWalletBalance(res.data.walletBalance);
        } catch {
          setWalletBalance(0);
        }
      }

      async function login() {
        setLoginError('');
        try {
          const res = await axios.post('/api/auth/login', { username, password });
          setToken(res.data.token);
          setUserRole(res.data.user.role);
          setAdminPromoted(res.data.user.role === 'admin');
          setUsername('');
          setPassword('');
        } catch {
          setLoginError('Login failed');
        }
      }

      async function placeBet() {
        if (!socket || betAmount <= 0 || betPlaced) return;
        socket.emit('place_bet', { roundId, amount: betAmount });
        setBetPlaced(true);
        addMessage(`Bet placed: ${betAmount}`);
      }

      async function cashOut() {
        if (!socket || cashedOut || !betPlaced) return;
        socket.emit('cashout', { roundId });
        setCashedOut(true);
        addMessage(`Cashed out at ${multiplierRef.current}x`);
      }

      function addMessage(msg) {
        setMessages(m => [...m.slice(-19), msg]);
      }

      if (!token) {
        if (showRegister) {
          return e(Fragment, null,
            e(Register, { onRegistered: () => setShowRegister(false) }),
            e("div", { className: "text-center mt-4 text-white" },
              "Already have an account? ",
              e("button", {
                onClick: () => setShowRegister(false),
                className: "underline hover:text-gray-300"
              }, "Login here")
            )
          );
        }
        return e("div", { className: "min-h-screen flex flex-col items-center justify-center bg-gray-900 text-white p-4" },
          e("h1", { className: "text-3xl font-bold mb-6" }, "Aviator Crash Game"),
          e("input", {
            type: "text",
            placeholder: "Username",
            className: "mb-2 p-2 rounded text-black w-64",
            value: username,
            onChange: e => setUsername(e.target.value)
          }),
          e("input", {
            type: "password",
            placeholder: "Password",
            className: "mb-4 p-2 rounded text-black w-64",
            value: password,
            onChange: e => setPassword(e.target.value)
          }),
          e("button", {
            onClick: login,
            className: "bg-green-600 px-6 py-2 rounded hover:bg-green-700 transition"
          }, "Login"),
          loginError && e("p", { className: "mt-4 text-yellow-400" }, loginError),
          e("div", { className: "text-center mt-4" },
            "Don't have an account? ",
            e("button", {
              onClick: () => setShowRegister(true),
              className: "underline hover:text-gray-300"
            }, "Register here")
          )
        );
      }

      return e(BrowserRouter, null,
        e("nav", { className: "bg-gray-800 p-3 flex justify-between items-center text-white max-w-md mx-auto rounded mb-4" },
          e(Link, { to: "/", className: "font-bold text-lg" }, "Aviator Crash"),
          e("div", { className: "space-x-4" },
            e(Link, { to: "/", className: "hover:underline" }, "Game"),
            userRole === 'admin' && e(Link, { to: "/admin", className: "hover:underline" }, "Admin Panel"),
            e("button", {
              onClick: () => {
                setToken(null);
                setUserRole(null);
                setAdminPromoted(false);
                setSocket(null);
                setMessages([]);
              },
              className: "hover:underline"
            }, "Logout")
          )
        ),
        e("div", { className: "max-w-md mx-auto" },
          e(Routes, null,
            e(Route, {
              path: "/",
              element: e(Fragment, null,
                e(Wallet, { token: token, onBalanceChange: setWalletBalance }),
                e(KYC, { token: token }),
                !adminPromoted && userRole !== 'admin' && e(PromoteSelf, {
                  token: token,
                  onPromoted: () => {
                    setUserRole('admin');
                    setAdminPromoted(true);
                  }
                }),
                e("div", { className: "bg-gray-800 rounded p-4 mb-4 flex flex-col items-center" },
                  e("div", { className: "text-sm mb-1" }, "Round ID: ", roundId),
                  e("div", { className: "text-xs mb-2 break-all" }, "Server Seed Hash: ", serverSeedHash),
                  e("div", { className: "text-6xl font-extrabold mb-2" }, multiplier.toFixed(2), "x"),
                  crashMultiplier && e("div", { className: "text-red-500 font-bold mb-2" }, "Crashed at ", crashMultiplier.toFixed(2), "x"),
                  e("div", { className: "flex space-x-2" },
                    e("input", {
                      type: "number",
                      min: 0.01,
                      step: 0.01,
                      disabled: betPlaced || !betCloseIn,
                      className: "p-2 rounded text-black w-24",
                      placeholder: "Bet amount",
                      value: betAmount > 0 ? betAmount : '',
                      onChange: e => setBetAmount(parseFloat(e.target.value))
                    }),
                    e("button", {
                      disabled: betPlaced || !betCloseIn || betAmount <= 0 || betAmount > walletBalance,
                      onClick: placeBet,
                      className: "bg-blue-600 px-4 py-2 rounded disabled:opacity-50"
                    }, "Place Bet"),
                    e("button", {
                      disabled: !betPlaced || cashedOut || multiplier <= 1,
                      onClick: cashOut,
                      className: "bg-yellow-500 px-4 py-2 rounded disabled:opacity-50"
                    }, "Cash Out")
                  )
                ),
                e(ProvablyFairVerification, null),
                e("div", { className: "bg-gray-800 rounded p-4 flex-1 overflow-auto" },
                  e("h2", { className: "text-lg font-semibold mb-2" }, "Messages"),
                  e("ul", { className: "text-sm space-y-1 max-h-48 overflow-y-auto" },
                    messages.map((m, i) => e("li", { key: i }, m))
                  )
                )
              )
            }),
            e(Route, {
              path: "/admin",
              element: userRole === 'admin' ? e(AdminPanel, { token: token }) : e(Navigate, { to: "/", replace: true })
            }),
            e(Route, { path: "*", element: e(Navigate, { to: "/", replace: true }) })
          )
        )
      );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(e(App));
  </script>
</body>
</html>
