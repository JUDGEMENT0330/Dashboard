import React, { useState, useCallback, useEffect } from 'react';
import { Shield, BookOpen, Search, AlertTriangle, CheckCircle, XCircle, Upload, Loader, ExternalLink, Lock, Code, FileJson, Menu, X } from 'lucide-react';

// ========================
// DATOS EDUCATIVOS
// ========================
const vulnerabilitiesData = [
  {
    id: 'broken-access-control',
    name: 'Broken Access Control',
    severity: 'critical',
    description: 'Falla en la implementación de restricciones sobre lo que los usuarios autenticados pueden hacer.',
    whatIs: 'El control de acceso roto permite a los atacantes acceder a funcionalidades o datos para los que no tienen permisos. Esto puede incluir acceder a cuentas de otros usuarios, modificar datos, o ejecutar funciones administrativas.',
    vulnerableCode: `// ❌ Código Vulnerable
app.get('/api/user/:id/profile', async (req, res) => {
  // No valida si el usuario tiene permiso para ver este perfil
  const userId = req.params.id;
  const profile = await db.getUserProfile(userId);
  res.json(profile);
});

// El atacante puede cambiar el ID en la URL para ver cualquier perfil`,
    secureCode: `// ✅ Código Seguro
app.get('/api/user/:id/profile', authenticateUser, async (req, res) => {
  const requestedUserId = req.params.id;
  const currentUserId = req.user.id;
  
  // Verifica que el usuario solo acceda a su propio perfil
  // o que tenga rol de administrador
  if (requestedUserId !== currentUserId && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  
  const profile = await db.getUserProfile(requestedUserId);
  res.json(profile);
});`
  },
  {
    id: 'cryptographic-failures',
    name: 'Cryptographic Failures',
    severity: 'critical',
    description: 'Fallas relacionadas con la criptografía que conducen a la exposición de datos sensibles.',
    whatIs: 'Los fallos criptográficos incluyen almacenar datos sensibles en texto plano, usar algoritmos débiles, o implementar incorrectamente la criptografía. Esto puede exponer contraseñas, números de tarjetas de crédito, y otros datos personales.',
    vulnerableCode: `// ❌ Código Vulnerable
const bcrypt = require('bcrypt');

// Almacena contraseñas en texto plano
async function createUser(username, password) {
  await db.users.insert({
    username: username,
    password: password  // ¡Almacenado sin hash!
  });
}

// Usa MD5 (algoritmo roto)
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');`,
    secureCode: `// ✅ Código Seguro
const bcrypt = require('bcrypt');

// Usa bcrypt con salt rounds apropiados
async function createUser(username, password) {
  const saltRounds = 12;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  
  await db.users.insert({
    username: username,
    password: hashedPassword  // Hash seguro
  });
}

// Para verificar el login
async function verifyUser(username, password) {
  const user = await db.users.findOne({ username });
  const isValid = await bcrypt.compare(password, user.password);
  return isValid;
}`
  },
  {
    id: 'injection',
    name: 'Injection (SQL, NoSQL, Command)',
    severity: 'critical',
    description: 'Envío de datos no confiables a un intérprete como parte de un comando o consulta.',
    whatIs: 'Las vulnerabilidades de inyección ocurren cuando datos no validados son enviados a un intérprete. SQL Injection es la más común, permitiendo al atacante ejecutar comandos SQL arbitrarios en la base de datos.',
    vulnerableCode: `// ❌ Código Vulnerable (SQL Injection)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Concatenación directa de strings - MUY PELIGROSO
  const query = \`
    SELECT * FROM users 
    WHERE username = '\${username}' 
    AND password = '\${password}'
  \`;
  
  const user = await db.query(query);
  // Atacante puede inyectar: ' OR '1'='1' --
});`,
    secureCode: `// ✅ Código Seguro (Consultas Parametrizadas)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Usa consultas parametrizadas o prepared statements
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  const user = await db.query(query, [username, password]);
  
  // O usando un ORM como Sequelize
  const user = await User.findOne({
    where: {
      username: username,
      password: password
    }
  });
});`
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    description: 'Permite a atacantes inyectar scripts maliciosos en páginas web vistas por otros usuarios.',
    whatIs: 'XSS ocurre cuando una aplicación incluye datos no validados en una página web sin escapar adecuadamente. Los atacantes pueden robar cookies de sesión, redirigir usuarios, o modificar el contenido de la página.',
    vulnerableCode: `// ❌ Código Vulnerable
function displayComment(comment) {
  // Inserta HTML directamente sin sanitizar
  document.getElementById('comments').innerHTML += \`
    <div class="comment">
      <p>\${comment.text}</p>
      <span>Por: \${comment.author}</span>
    </div>
  \`;
}

// Un atacante puede enviar: <script>alert(document.cookie)</script>`,
    secureCode: `// ✅ Código Seguro
function displayComment(comment) {
  // Opción 1: Usa textContent en lugar de innerHTML
  const div = document.createElement('div');
  div.className = 'comment';
  
  const p = document.createElement('p');
  p.textContent = comment.text;  // Escapa automáticamente
  
  const span = document.createElement('span');
  span.textContent = 'Por: ' + comment.author;
  
  div.appendChild(p);
  div.appendChild(span);
  document.getElementById('comments').appendChild(div);
}

// Opción 2: Usa una librería como DOMPurify
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(comment.text);`
  },
  {
    id: 'insecure-design',
    name: 'Insecure Design',
    severity: 'high',
    description: 'Fallas en el diseño y arquitectura de la aplicación que no pueden arreglarse solo con implementación.',
    whatIs: 'El diseño inseguro representa fallas en la lógica de negocio y arquitectura. Por ejemplo, un sistema de recuperación de contraseña que permite enumerar usuarios válidos, o un proceso de pago que permite modificar precios.',
    vulnerableCode: `// ❌ Código Vulnerable
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) {
    // Revela si el email existe en el sistema
    return res.status(404).json({ 
      error: 'Email no encontrado' 
    });
  }
  
  await sendPasswordResetEmail(user);
  res.json({ message: 'Email enviado' });
});`,
    secureCode: `// ✅ Código Seguro
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  // No revela si el email existe o no
  // Siempre responde igual
  const user = await User.findOne({ email });
  
  if (user) {
    await sendPasswordResetEmail(user);
  }
  
  // Respuesta genérica que no revela información
  res.json({ 
    message: 'Si el email existe, recibirás instrucciones de recuperación' 
  });
  
  // Opcionalmente: implementa rate limiting
  // y CAPTCHA para prevenir abuso
});`
  },
  {
    id: 'security-misconfiguration',
    name: 'Security Misconfiguration',
    severity: 'high',
    description: 'Configuraciones de seguridad incorrectas, incompletas o con valores por defecto.',
    whatIs: 'Las configuraciones incorrectas incluyen mostrar stack traces detallados en producción, tener servicios no utilizados habilitados, usar credenciales por defecto, o tener permisos mal configurados.',
    vulnerableCode: `// ❌ Código Vulnerable
// Configuración de Express en producción
const express = require('express');
const app = express();

// Muestra errores detallados en producción
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack  // ¡Expone información sensible!
  });
});

// Headers inseguros
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Express 4.18.0');  // Revela versión
  next();
});`,
    secureCode: `// ✅ Código Seguro
const express = require('express');
const helmet = require('helmet');
const app = express();

// Usa Helmet para configurar headers seguros
app.use(helmet());

// Manejo de errores apropiado según el entorno
if (process.env.NODE_ENV === 'production') {
  app.use((err, req, res, next) => {
    // Log del error internamente
    console.error(err);
    
    // Respuesta genérica al cliente
    res.status(500).json({
      error: 'Error interno del servidor'
    });
  });
} else {
  app.use((err, req, res, next) => {
    res.status(500).json({
      error: err.message,
      stack: err.stack
    });
  });
}`
  },
  {
    id: 'vulnerable-components',
    name: 'Vulnerable and Outdated Components',
    severity: 'high',
    description: 'Uso de componentes con vulnerabilidades conocidas, sin parches, o no soportados.',
    whatIs: 'Usar bibliotecas y frameworks con vulnerabilidades conocidas es extremadamente común. Los atacantes buscan activamente aplicaciones que usen versiones vulnerables de componentes populares.',
    vulnerableCode: `// ❌ Código Vulnerable
// package.json con dependencias desactualizadas
{
  "dependencies": {
    "express": "4.16.0",  // Vulnerable a DoS
    "lodash": "4.17.15",  // Prototype Pollution
    "jquery": "3.3.1",    // XSS vulnerabilities
    "axios": "0.18.0"     // SSRF vulnerability
  }
}

// No hay proceso de actualización
// No se monitorean vulnerabilidades`,
    secureCode: `// ✅ Código Seguro
// package.json con dependencias actualizadas
{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21",
    "jquery": "^3.7.0",
    "axios": "^1.6.0"
  },
  "scripts": {
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "update-check": "npm-check-updates"
  }
}

// Proceso recomendado:
// 1. Ejecuta 'npm audit' regularmente
// 2. Usa herramientas como Snyk o Dependabot
// 3. Mantén un calendario de actualizaciones
// 4. Revisa el changelog antes de actualizar`
  },
  {
    id: 'auth-failures',
    name: 'Identification and Authentication Failures',
    severity: 'critical',
    description: 'Fallas en la confirmación de identidad, autenticación, o manejo de sesiones.',
    whatIs: 'Las fallas de autenticación permiten a atacantes comprometer contraseñas, claves, tokens de sesión, o explotar otras fallas para asumir temporalmente o permanentemente la identidad de otros usuarios.',
    vulnerableCode: `// ❌ Código Vulnerable
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Sin rate limiting - permite fuerza bruta
  const user = await User.findOne({ username, password });
  
  if (user) {
    // Session ID predecible
    const sessionId = Date.now().toString();
    
    // Cookie sin flags de seguridad
    res.cookie('sessionId', sessionId);
    res.json({ success: true });
  }
});

// No hay timeout de sesión
// No hay autenticación de dos factores`,
    secureCode: `// ✅ Código Seguro
const rateLimit = require('express-rate-limit');
const session = require('express-session');

// Rate limiting para prevenir fuerza bruta
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutos
  max: 5,  // 5 intentos
  message: 'Demasiados intentos de login'
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,      // Solo HTTPS
    httpOnly: true,    // No accesible via JavaScript
    maxAge: 3600000,   // 1 hora
    sameSite: 'strict'
  }
}));

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password, totpToken } = req.body;
  
  const user = await User.findOne({ username });
  const isValidPassword = await bcrypt.compare(password, user.password);
  
  if (!isValidPassword) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  
  // Verifica 2FA si está habilitado
  if (user.twoFactorEnabled) {
    const isValidToken = verifyTOTP(user.totpSecret, totpToken);
    if (!isValidToken) {
      return res.status(401).json({ error: 'Token 2FA inválido' });
    }
  }
  
  req.session.userId = user.id;
  res.json({ success: true });
});`
  }
];

// ========================
// HOOK PERSONALIZADO PARA OSV API
// ========================
const useOsvScanner = () => {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const scanDependencies = async (dependencies) => {
    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const packageList = Object.entries(dependencies).map(([name, version]) => ({
        name,
        version: version.replace(/^[\^~]/, '')
      }));

      const promises = packageList.map(async (pkg) => {
        try {
          const response = await fetch('https://api.osv.dev/v1/query', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              version: pkg.version,
              package: {
                name: pkg.name,
                ecosystem: 'npm'
              }
            })
          });

          const data = await response.json();
          
          return {
            package: pkg.name,
            version: pkg.version,
            vulnerabilities: data.vulns || [],
            status: data.vulns && data.vulns.length > 0 ? 'vulnerable' : 'safe'
          };
        } catch (err) {
          return {
            package: pkg.name,
            version: pkg.version,
            vulnerabilities: [],
            status: 'error',
            error: err.message
          };
        }
      });

      const scanResults = await Promise.allSettled(promises);
      const processedResults = scanResults.map(result => 
        result.status === 'fulfilled' ? result.value : { status: 'error' }
      );

      const summary = {
        total: processedResults.length,
        vulnerable: processedResults.filter(r => r.status === 'vulnerable').length,
        safe: processedResults.filter(r => r.status === 'safe').length,
        errors: processedResults.filter(r => r.status === 'error').length
      };

      setResults({
        summary,
        packages: processedResults
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return { scanDependencies, loading, results, error };
};

// ========================
// COMPONENTES
// ========================

// Sidebar de navegación con diseño responsivo
const Sidebar = ({ currentPage, setCurrentPage, isOpen, setIsOpen }) => {
  const menuItems = [
    { id: 'home', icon: Shield, label: 'Inicio' },
    { id: 'education', icon: BookOpen, label: 'Educación' },
    { id: 'scanner', icon: Search, label: 'Escáner' }
  ];

  return (
    <>
      {/* Overlay para móvil */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
      
      {/* Sidebar */}
      <div className={`
        fixed lg:sticky top-0 left-0 h-screen z-50
        w-64 bg-gradient-to-b from-slate-900/95 to-slate-800/95
        backdrop-blur-xl border-r border-white/10
        text-white shadow-2xl
        transform transition-transform duration-300 ease-in-out
        ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        <div className="p-6">
          {/* Header con botón de cierre móvil */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <Shield className="w-10 h-10 text-indigo-400" />
              <div>
                <h1 className="text-xl font-bold">SecureDev</h1>
                <p className="text-xs text-indigo-300">Dashboard</p>
              </div>
            </div>
            <button 
              onClick={() => setIsOpen(false)}
              className="lg:hidden text-white/70 hover:text-white"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
          
          <nav className="space-y-2">
            {menuItems.map(item => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentPage(item.id);
                    setIsOpen(false); // Cerrar sidebar en móvil al navegar
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                    currentPage === item.id
                      ? 'bg-white/20 backdrop-blur-sm text-white shadow-lg border border-white/20'
                      : 'text-indigo-100 hover:bg-white/10 hover:backdrop-blur-sm'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
        
        <div className="absolute bottom-0 left-0 right-0 p-6 border-t border-white/10 bg-black/20 backdrop-blur-sm">
          <div className="flex items-center gap-2 text-xs text-indigo-300">
            <Lock className="w-4 h-4" />
            <span>Modo Defensivo</span>
          </div>
        </div>
      </div>
    </>
  );
};

// Botón de menú móvil
const MobileMenuButton = ({ onClick }) => (
  <button
    onClick={onClick}
    className="lg:hidden fixed top-4 left-4 z-30 p-3 bg-slate-900/90 backdrop-blur-xl rounded-lg border border-white/10 shadow-lg"
  >
    <Menu className="w-6 h-6 text-white" />
  </button>
);

// Página de inicio
const HomePage = () => {
  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-indigo-600 via-purple-600 to-pink-600 rounded-2xl p-6 sm:p-12 text-white mb-8 shadow-2xl">
        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-4">
          Bienvenido a SecureDev Dashboard
        </h1>
        <p className="text-lg sm:text-xl text-indigo-100 mb-6">
          Plataforma educativa para escribir código más seguro mediante análisis defensivo
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 sm:px-6 py-4 border border-white/20">
            <div className="text-2xl sm:text-3xl font-bold">OWASP Top 10</div>
            <div className="text-xs sm:text-sm">Vulnerabilidades cubiertas</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 sm:px-6 py-4 border border-white/20">
            <div className="text-2xl sm:text-3xl font-bold">OSV.dev</div>
            <div className="text-xs sm:text-sm">Base de datos de vulnerabilidades</div>
          </div>
        </div>
      </div>

      {/* Features Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-6 shadow-xl border border-white/10">
          <div className="flex items-center gap-3 mb-4">
            <BookOpen className="w-8 h-8 text-indigo-400" />
            <h2 className="text-xl sm:text-2xl font-bold text-white">Módulo Educativo</h2>
          </div>
          <p className="text-gray-300 mb-4 text-sm sm:text-base">
            Aprende sobre las vulnerabilidades más críticas con ejemplos de código vulnerable y seguro.
          </p>
          <ul className="space-y-2 text-sm text-gray-300">
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>Explicaciones simples y claras</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>Ejemplos de código real</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>Soluciones y mitigaciones</span>
            </li>
          </ul>
        </div>

        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-6 shadow-xl border border-white/10">
          <div className="flex items-center gap-3 mb-4">
            <Search className="w-8 h-8 text-purple-400" />
            <h2 className="text-xl sm:text-2xl font-bold text-white">Escáner de Dependencias</h2>
          </div>
          <p className="text-gray-300 mb-4 text-sm sm:text-base">
            Analiza tu archivo package.json para detectar vulnerabilidades conocidas en tus dependencias.
          </p>
          <ul className="space-y-2 text-sm text-gray-300">
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>Escaneo en tiempo real con OSV.dev</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>Reporte detallado de severidad</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>Enlaces a CVE y reportes</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Warning Banner */}
      <div className="bg-amber-900/20 backdrop-blur-xl border border-amber-500/30 rounded-lg p-4 sm:p-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0 mt-1" />
          <div>
            <h3 className="text-lg font-bold text-amber-200 mb-2">Aviso Ético</h3>
            <p className="text-sm text-amber-100">
              Esta herramienta está diseñada estrictamente para fines educativos y defensivos. 
              Solo debe usarse para analizar proyectos de los que se es propietario o se tiene 
              permiso explícito para evaluar. El uso de técnicas de seguridad sin autorización es ilegal.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

// Tarjeta de vulnerabilidad con glassmorphism
const VulnerabilityCard = ({ vuln, onClick }) => {
  const severityColors = {
    critical: 'from-red-500 to-red-600',
    high: 'from-orange-500 to-orange-600',
    medium: 'from-yellow-500 to-yellow-600',
    low: 'from-blue-500 to-blue-600'
  };

  return (
    <button
      onClick={onClick}
      className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-4 sm:p-6 shadow-xl hover:shadow-2xl transition-all border border-white/10 hover:border-white/20 text-left w-full group"
    >
      <div className="flex flex-col sm:flex-row items-start justify-between gap-3 mb-3">
        <h3 className="text-base sm:text-lg font-bold text-white group-hover:text-indigo-400 transition-colors">
          {vuln.name}
        </h3>
        <span className={`px-3 py-1 rounded-full text-xs font-bold text-white bg-gradient-to-r ${severityColors[vuln.severity]} flex-shrink-0`}>
          {vuln.severity.toUpperCase()}
        </span>
      </div>
      <p className="text-sm text-gray-300">{vuln.description}</p>
    </button>
  );
};

// Página de detalle de vulnerabilidad
const VulnerabilityDetail = ({ vuln, onBack }) => {
  const [activeTab, setActiveTab] = useState('whatIs');

  const tabs = [
    { id: 'whatIs', label: '¿Qué es?', icon: BookOpen },
    { id: 'vulnerable', label: 'Vulnerable', icon: XCircle },
    { id: 'secure', label: 'Seguro', icon: CheckCircle }
  ];

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <button
        onClick={onBack}
        className="mb-6 flex items-center gap-2 text-indigo-400 hover:text-indigo-300 font-medium text-sm sm:text-base"
      >
        ← Volver a la lista
      </button>

      <div className="bg-slate-900/40 backdrop-blur-xl rounded-2xl shadow-2xl overflow-hidden border border-white/10">
        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-6 sm:p-8 text-white">
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold mb-3">{vuln.name}</h1>
          <p className="text-base sm:text-lg text-indigo-100">{vuln.description}</p>
        </div>

        {/* Tabs */}
        <div className="border-b border-white/10 bg-slate-900/60">
          <div className="flex overflow-x-auto">
            {tabs.map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 sm:px-6 py-3 sm:py-4 font-medium transition-colors whitespace-nowrap text-sm sm:text-base ${
                    activeTab === tab.id
                      ? 'bg-slate-800/60 text-indigo-400 border-b-2 border-indigo-400'
                      : 'text-gray-400 hover:text-gray-300 hover:bg-slate-800/40'
                  }`}
                >
                  <Icon className="w-4 h-4 sm:w-5 sm:h-5" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Content */}
        <div className="p-4 sm:p-8">
          {activeTab === 'whatIs' && (
            <div className="prose prose-invert max-w-none">
              <p className="text-base sm:text-lg text-gray-200 leading-relaxed">{vuln.whatIs}</p>
            </div>
          )}

          {activeTab === 'vulnerable' && (
            <div>
              <div className="bg-red-900/20 backdrop-blur-sm border border-red-500/30 p-4 mb-4 rounded-lg">
                <div className="flex items-center gap-2 text-red-300 font-bold mb-2 text-sm sm:text-base">
                  <XCircle className="w-5 h-5 flex-shrink-0" />
                  Código Vulnerable - NO usar en producción
                </div>
              </div>
              <pre className="bg-black/60 backdrop-blur-sm text-gray-100 p-4 sm:p-6 rounded-lg overflow-x-auto text-xs sm:text-sm border border-white/10">
                <code>{vuln.vulnerableCode}</code>
              </pre>
            </div>
          )}

          {activeTab === 'secure' && (
            <div>
              <div className="bg-green-900/20 backdrop-blur-sm border border-green-500/30 p-4 mb-4 rounded-lg">
                <div className="flex items-center gap-2 text-green-300 font-bold mb-2 text-sm sm:text-base">
                  <CheckCircle className="w-5 h-5 flex-shrink-0" />
                  Código Seguro - Implementación recomendada
                </div>
              </div>
              <pre className="bg-black/60 backdrop-blur-sm text-gray-100 p-4 sm:p-6 rounded-lg overflow-x-auto text-xs sm:text-sm border border-white/10">
                <code>{vuln.secureCode}</code>
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Página de educación
const EducationPage = () => {
  const [selectedVuln, setSelectedVuln] = useState(null);

  if (selectedVuln) {
    return (
      <VulnerabilityDetail
        vuln={selectedVuln}
        onBack={() => setSelectedVuln(null)}
      />
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="mb-8">
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">Módulo Educativo</h1>
        <p className="text-base sm:text-lg text-gray-300">
          Aprende sobre las vulnerabilidades más críticas del OWASP Top 10 con ejemplos prácticos
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        {vulnerabilitiesData.map(vuln => (
          <VulnerabilityCard
            key={vuln.id}
            vuln={vuln}
            onClick={() => setSelectedVuln(vuln)}
          />
        ))}
      </div>
    </div>
  );
};

// Componente Dropzone mejorado
const FileDropzone = ({ onFileDrop }) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files[0];
    if (file) {
      handleFile(file);
    }
  };

  const handleFileInput = (e) => {
    const file = e.target.files[0];
    if (file) {
      handleFile(file);
    }
  };

  const handleFile = (file) => {
    if (file.name !== 'package.json') {
      alert('Por favor, sube un archivo package.json válido');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = JSON.parse(e.target.result);
        if (!content.dependencies && !content.devDependencies) {
          alert('El archivo package.json no contiene dependencias');
          return;
        }
        onFileDrop(content);
      } catch (err) {
        alert('Error al leer el archivo: ' + err.message);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`border-2 border-dashed rounded-2xl p-8 sm:p-12 text-center transition-all ${
        isDragging
          ? 'border-indigo-400 bg-indigo-900/20 backdrop-blur-xl'
          : 'border-white/20 bg-slate-900/40 backdrop-blur-xl hover:border-indigo-400/50 hover:bg-slate-900/60'
      }`}
    >
      <FileJson className="w-16 h-16 sm:w-20 sm:h-20 mx-auto mb-4 text-indigo-400" />
      <h3 className="text-xl sm:text-2xl font-bold text-white mb-2">
        Arrastra tu archivo package.json aquí
      </h3>
      <p className="text-gray-300 mb-6 text-sm sm:text-base">o haz clic para seleccionar un archivo</p>
      <label className="inline-block">
        <input
          type="file"
          accept=".json"
          onChange={handleFileInput}
          className="hidden"
        />
        <span className="bg-indigo-600 text-white px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors cursor-pointer inline-flex items-center gap-2 text-sm sm:text-base">
          <Upload className="w-4 h-4 sm:w-5 sm:h-5" />
          Seleccionar archivo
        </span>
      </label>
    </div>
  );
};

// Tabla de resultados con glassmorphism oscuro
const ResultsTable = ({ results }) => {
  const getSeverityColor = (severity) => {
    if (!severity) return 'bg-gray-700/50 text-gray-300';
    const sev = severity.toLowerCase();
    if (sev.includes('critical')) return 'bg-red-900/50 text-red-300';
    if (sev.includes('high')) return 'bg-orange-900/50 text-orange-300';
    if (sev.includes('medium')) return 'bg-yellow-900/50 text-yellow-300';
    return 'bg-blue-900/50 text-blue-300';
  };

  return (
    <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl shadow-2xl overflow-hidden border border-white/10">
      {/* Header con glassmorphism */}
      <div className="bg-gradient-to-r from-indigo-600/90 to-purple-600/90 backdrop-blur-xl p-4 sm:p-6 text-white border-b border-white/10">
        <h2 className="text-xl sm:text-2xl font-bold mb-3">Resultados del Escaneo</h2>
        <div className="grid grid-cols-3 gap-2 sm:gap-4">
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 border border-white/20">
            <div className="text-2xl sm:text-3xl font-bold">{results.summary.total}</div>
            <div className="text-xs sm:text-sm">Paquetes</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 border border-white/20">
            <div className="text-2xl sm:text-3xl font-bold">{results.summary.vulnerable}</div>
            <div className="text-xs sm:text-sm">Vulnerables</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 border border-white/20">
            <div className="text-2xl sm:text-3xl font-bold">{results.summary.safe}</div>
            <div className="text-xs sm:text-sm">Seguros</div>
          </div>
        </div>
      </div>

      {/* Tabla responsiva */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-slate-900/60 backdrop-blur-sm border-b border-white/10">
            <tr>
              <th className="px-3 sm:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-bold text-gray-300">Estado</th>
              <th className="px-3 sm:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-bold text-gray-300">Paquete</th>
              <th className="px-3 sm:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-bold text-gray-300 hidden sm:table-cell">Versión</th>
              <th className="px-3 sm:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-bold text-gray-300">Vulns</th>
              <th className="px-3 sm:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-bold text-gray-300 hidden md:table-cell">Severidad</th>
              <th className="px-3 sm:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-bold text-gray-300 hidden lg:table-cell">Detalles</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {results.packages.map((pkg, idx) => (
              <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                <td className="px-3 sm:px-6 py-3 sm:py-4">
                  {pkg.status === 'vulnerable' && (
                    <div className="flex items-center gap-2 text-red-400">
                      <XCircle className="w-4 h-4 sm:w-5 sm:h-5 flex-shrink-0" />
                      <span className="font-medium text-xs sm:text-sm hidden sm:inline">Vulnerable</span>
                    </div>
                  )}
                  {pkg.status === 'safe' && (
                    <div className="flex items-center gap-2 text-green-400">
                      <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 flex-shrink-0" />
                      <span className="font-medium text-xs sm:text-sm hidden sm:inline">Seguro</span>
                    </div>
                  )}
                  {pkg.status === 'error' && (
                    <div className="flex items-center gap-2 text-gray-400">
                      <AlertTriangle className="w-4 h-4 sm:w-5 sm:h-5 flex-shrink-0" />
                      <span className="font-medium text-xs sm:text-sm hidden sm:inline">Error</span>
                    </div>
                  )}
                </td>
                <td className="px-3 sm:px-6 py-3 sm:py-4">
                  <div className="font-mono text-xs sm:text-sm text-white break-all">{pkg.package}</div>
                  <div className="font-mono text-xs text-gray-400 sm:hidden">{pkg.version}</div>
                </td>
                <td className="px-3 sm:px-6 py-3 sm:py-4 font-mono text-xs sm:text-sm text-gray-400 hidden sm:table-cell">{pkg.version}</td>
                <td className="px-3 sm:px-6 py-3 sm:py-4">
                  {pkg.vulnerabilities.length > 0 ? (
                    <span className="font-bold text-red-400 text-sm sm:text-base">{pkg.vulnerabilities.length}</span>
                  ) : (
                    <span className="text-gray-500 text-sm sm:text-base">0</span>
                  )}
                </td>
                <td className="px-3 sm:px-6 py-3 sm:py-4 hidden md:table-cell">
                  {pkg.vulnerabilities.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {pkg.vulnerabilities.slice(0, 2).map((vuln, vidx) => (
                        <span
                          key={vidx}
                          className={`px-2 py-1 rounded text-xs font-medium backdrop-blur-sm ${getSeverityColor(
                            vuln.severity?.[0]?.score || vuln.database_specific?.severity
                          )}`}
                        >
                          {vuln.severity?.[0]?.score || vuln.database_specific?.severity || 'N/A'}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-500">-</span>
                  )}
                </td>
                <td className="px-3 sm:px-6 py-3 sm:py-4 hidden lg:table-cell">
                  {pkg.vulnerabilities.length > 0 && (
                    <div className="flex flex-col gap-1">
                      {pkg.vulnerabilities.slice(0, 2).map((vuln, vidx) => (
                        <a
                          key={vidx}
                          href={vuln.references?.[0]?.url || vuln.database_specific?.url || '#'}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300 text-xs sm:text-sm"
                        >
                          <ExternalLink className="w-3 h-3 sm:w-4 sm:h-4 flex-shrink-0" />
                          <span className="font-mono truncate">{vuln.id || 'Ver más'}</span>
                        </a>
                      ))}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Página de escáner
const ScannerPage = () => {
  const { scanDependencies, loading, results, error } = useOsvScanner();
  const [packageData, setPackageData] = useState(null);

  const handleFileDrop = (data) => {
    setPackageData(data);
    
    const allDeps = {
      ...data.dependencies,
      ...data.devDependencies
    };
    
    scanDependencies(allDeps);
  };

  const handleReset = () => {
    setPackageData(null);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="mb-8">
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">Escáner de Dependencias</h1>
        <p className="text-base sm:text-lg text-gray-300">
          Analiza tu archivo package.json para detectar vulnerabilidades conocidas usando OSV.dev
        </p>
      </div>

      {!results && !loading && (
        <>
          <FileDropzone onFileDrop={handleFileDrop} />
          
          <div className="mt-8 bg-blue-900/20 backdrop-blur-xl border border-blue-500/30 rounded-xl p-4 sm:p-6">
            <h3 className="text-base sm:text-lg font-bold text-blue-200 mb-3 flex items-center gap-2">
              <Code className="w-5 h-5" />
              Cómo usar el escáner
            </h3>
            <ol className="space-y-2 text-sm sm:text-base text-blue-100">
              <li className="flex items-start gap-2">
                <span className="font-bold flex-shrink-0">1.</span>
                <span>Localiza el archivo <code className="bg-blue-800/40 px-2 py-1 rounded">package.json</code> de tu proyecto Node.js</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-bold flex-shrink-0">2.</span>
                <span>Arrastra el archivo a la zona de arriba o haz clic para seleccionarlo</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-bold flex-shrink-0">3.</span>
                <span>Espera mientras consultamos la base de datos de OSV.dev</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-bold flex-shrink-0">4.</span>
                <span>Revisa los resultados y toma acción sobre las vulnerabilidades encontradas</span>
              </li>
            </ol>
          </div>
        </>
      )}

      {loading && (
        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-8 sm:p-12 text-center shadow-2xl border border-white/10">
          <Loader className="w-12 h-12 sm:w-16 sm:h-16 mx-auto mb-4 text-indigo-400 animate-spin" />
          <h3 className="text-xl sm:text-2xl font-bold text-white mb-2">Escaneando dependencias...</h3>
          <p className="text-gray-300 text-sm sm:text-base">Consultando la base de datos de OSV.dev</p>
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 backdrop-blur-xl border border-red-500/30 rounded-xl p-4 sm:p-6">
          <div className="flex items-center gap-3 text-red-300">
            <XCircle className="w-6 h-6 flex-shrink-0" />
            <div>
              <h3 className="font-bold text-sm sm:text-base">Error al escanear</h3>
              <p className="text-sm">{error}</p>
            </div>
          </div>
        </div>
      )}

      {results && (
        <>
          <ResultsTable results={results} />
          
          <div className="mt-6 flex justify-center">
            <button
              onClick={handleReset}
              className="bg-indigo-600 text-white px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors text-sm sm:text-base"
            >
              Escanear otro archivo
            </button>
          </div>

          {results.summary.vulnerable > 0 && (
            <div className="mt-6 bg-amber-900/20 backdrop-blur-xl border border-amber-500/30 rounded-xl p-4 sm:p-6">
              <h3 className="text-base sm:text-lg font-bold text-amber-200 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Recomendaciones
              </h3>
              <ul className="space-y-2 text-sm sm:text-base text-amber-100">
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0">•</span>
                  <span>Actualiza los paquetes vulnerables a versiones que no contengan las vulnerabilidades reportadas</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0">•</span>
                  <span>Si no hay versión actualizada, considera usar un paquete alternativo</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0">•</span>
                  <span>Ejecuta <code className="bg-amber-800/40 px-2 py-1 rounded">npm audit fix</code> para intentar arreglar automáticamente</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0">•</span>
                  <span>Revisa los enlaces a CVE para entender el impacto de cada vulnerabilidad</span>
                </li>
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// Componente principal con sidebar responsivo
const App = () => {
  const [currentPage, setCurrentPage] = useState('home');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <div className="flex">
        <Sidebar 
          currentPage={currentPage} 
          setCurrentPage={setCurrentPage}
          isOpen={isSidebarOpen}
          setIsOpen={setIsSidebarOpen}
        />
        
        <div className="flex-1 min-h-screen">
          <MobileMenuButton onClick={() => setIsSidebarOpen(true)} />
          
          <main className="pt-16 lg:pt-0">
            {currentPage === 'home' && <HomePage />}
            {currentPage === 'education' && <EducationPage />}
            {currentPage === 'scanner' && <ScannerPage />}
          </main>
        </div>
      </div>
    </div>
  );
};

export default App;
