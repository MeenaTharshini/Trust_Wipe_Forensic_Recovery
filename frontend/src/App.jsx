
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";

// =========================================================
// LAYOUT / COMPONENTS
// =========================================================

import Sidebar from "./components/Sidebar";
import PrivateRoute from "./components/PrivateRoute";

// =========================================================
// PAGES
// =========================================================

import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";

import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Verification from "./pages/Verification";
import Certificates from "./pages/Certificates";
import Reports from "./pages/Reports";
import Forensics from "./pages/Forensics";

import Services from "./pages/Services";
import About from "./pages/About";
import VerifyCertificate from "./pages/VerifyCertificate";

// =========================================================
// GLOBAL APP CSS
// =========================================================

import "./App.css";


// =========================================================
// APPLICATION LAYOUT
// =========================================================

function Layout() {
  const location = useLocation();

  /*
   * Routes that should NOT show the authenticated
   * dashboard sidebar.
   */
  const publicRoutes = [
    "/",
    "/login",
    "/register",
    "/services",
    "/about",
    "/verify",
    "/verify-certificate",
  ];

  /*
   * /verify/:id is also public.
   */
  const isVerifyRoute =
    location.pathname.startsWith("/verify/");

  const hideSidebar =
    publicRoutes.includes(location.pathname) ||
    isVerifyRoute;


  return (
    <div className="app-layout">

      {/* =====================================================
          SIDEBAR
          ===================================================== */}

      {!hideSidebar && <Sidebar />}


      {/* =====================================================
          MAIN CONTENT
          ===================================================== */}

      <main
        className={
          hideSidebar
            ? "auth-content"
            : "main-content"
        }
      >

        <Routes>

          {/* =================================================
              PUBLIC LANDING PAGE
              ================================================= */}

          <Route
            path="/"
            element={<Home />}
          />


          {/* =================================================
              PUBLIC INFORMATION PAGES
              ================================================= */}

          <Route
            path="/services"
            element={<Services />}
          />

          <Route
            path="/about"
            element={<About />}
          />


          {/* =================================================
              CERTIFICATE VERIFICATION
              ================================================= */}

          <Route
            path="/verify"
            element={<VerifyCertificate />}
          />

          <Route
            path="/verify/:id"
            element={<VerifyCertificate />}
          />

          {/* Backward compatibility */}
          <Route
            path="/verify-certificate"
            element={
              <Navigate
                to="/verify"
                replace
              />
            }
          />


          {/* =================================================
              AUTHENTICATION
              ================================================= */}

          <Route
            path="/login"
            element={<Login />}
          />

          <Route
            path="/register"
            element={<Register />}
          />


          {/* =================================================
              PROTECTED DASHBOARD
              ================================================= */}

          <Route
            path="/dashboard"
            element={
              <PrivateRoute>
                <Dashboard />
              </PrivateRoute>
            }
          />

          {/* Optional device-specific dashboard */}
          <Route
            path="/dashboard/:id"
            element={
              <PrivateRoute>
                <Dashboard />
              </PrivateRoute>
            }
          />


          {/* =================================================
              DEVICES
              ================================================= */}

          <Route
            path="/devices"
            element={
              <PrivateRoute>
                <Devices />
              </PrivateRoute>
            }
          />


          {/* =================================================
              WIPE VERIFICATION
              ================================================= */}

          <Route
            path="/verification"
            element={
              <PrivateRoute>
                <Verification />
              </PrivateRoute>
            }
          />


          {/* =================================================
              CERTIFICATES
              ================================================= */}

          <Route
            path="/certificates"
            element={
              <PrivateRoute>
                <Certificates />
              </PrivateRoute>
            }
          />


          {/* =================================================
              REPORTS
              ================================================= */}

          <Route
            path="/reports"
            element={
              <PrivateRoute>
                <Reports />
              </PrivateRoute>
            }
          />


          {/* =================================================
              FORENSIC RECOVERY
              ================================================= */}

          <Route
            path="/forensics"
            element={
              <PrivateRoute>
                <Forensics />
              </PrivateRoute>
            }
          />


          {/* =================================================
              LEGACY WIPE JOB ROUTE
              ================================================= */}

          <Route
            path="/wipe-jobs"
            element={
              <PrivateRoute>
                <Navigate
                  to="/dashboard"
                  replace
                />
              </PrivateRoute>
            }
          />


          {/* =================================================
              404
              ================================================= */}

          <Route
            path="*"
            element={
              <div className="not-found">

                <h1>404</h1>

                <h2>Page Not Found</h2>

                <p>
                  The page you are looking for
                  does not exist.
                </p>

                <button
                  className="btn btn-primary"
                  onClick={() =>
                    window.history.back()
                  }
                >
                  Go Back
                </button>

              </div>
            }
          />

        </Routes>

      </main>

    </div>
  );
}


// =========================================================
// APP
// =========================================================

function App() {
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  );
}

export default App;
