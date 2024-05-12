<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Keycloak Front App Example</title>

    <link rel="stylesheet" type="text/css" href="styles.css"/>
    <script>
        backendUrl = "<?php echo $_ENV["BACKEND_URL"] ?>";
    </script>
    <script src="<?php echo $_ENV["KEYCLOAK_URL"] ?>/js/keycloak.js"></script>
    <script src="app.js"></script>
</head>

<body>
    <div id="wrapper" class="wrapper" style="display: none;">
        <div id="anon" class="menu">
            <button id="loginBtn" name="loginBtn" onclick="keycloak.login()">Login</button>
        </div>

        <div id="authenticated" class="menu">
            <button id="logoutBtn" name="logoutBtn" onclick="keycloak.logout()">Logout</button>
            <button id="accountBtn" name="accountBtn" onclick="keycloak.accountManagement()">Account</button>
        </div>

        <div class="content">
            <button id="publicBtn" name="publicBtn" onclick="request('')">Invoke Public</button>
            <button id="securedBtn" name="securedBtn" onclick="request('api/users/')">Invoke Secured</button>
            <button id="adminBtn" name="adminBtn" onclick="request('admin')">Invoke Admin</button>

            <div class="message" id="message"></div>
            <div class="message" id="debug"></div>
        </div>
    </div>

    <div class="service">
        <div>Keycloak: <?php echo $_ENV["KEYCLOAK_URL"] ?></div>
        <div>Backend: <?php echo $_ENV["BACKEND_URL"] ?></div>
    </div>
</body>

</html>
