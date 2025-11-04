import React, { useState, useCallback, useEffect } from 'react';
import { Shield, BookOpen, Search, AlertTriangle, CheckCircle, XCircle, Upload, Loader, ExternalLink, Lock, Code, FileJson } from 'lucide-react';

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
        version: version.replace(/^[\^~]/, '') // Elimina ^ y ~
      }));

      // Consultar OSV API para cada paquete
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

// Sidebar de navegación
const Sidebar = ({ currentPage, setCurrentPage }) => {
  const menuItems = [
    { id: 'home', icon: Shield, label: 'Inicio' },
    { id: 'education', icon: BookOpen, label: 'Educación' },
    { id: 'scanner', icon: Search, label: 'Escáner' }
  ];

  return (
    <div className="w-64 bg-gradient-to-b from-indigo-900 to-indigo-800 text-white h-screen fixed left-0 top-0 shadow-2xl">
      <div className="p-6">
        <div className="flex items-center gap-3 mb-8">
          <Shield className="w-10 h-10" />
          <div>
            <h1 className="text-xl font-bold">SecureDev</h1>
            <p className="text-xs text-indigo-300">Dashboard</p>
          </div>
        </div>
        
        <nav className="space-y-2">
          {menuItems.map(item => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                  currentPage === item.id
                    ? 'bg-white text-indigo-900 shadow-lg'
                    : 'text-indigo-100 hover:bg-indigo-700'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
      
      <div className="absolute bottom-0 left-0 right-0 p-6 border-t border-indigo-700">
        <div className="flex items-center gap-2 text-xs text-indigo-300">
          <Lock className="w-4 h-4" />
          <span>Modo Defensivo</span>
        </div>
      </div>
    </div>
  );
};

// Página de inicio
const HomePage = () => {
  return (
    <div className="max-w-6xl mx-auto">
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 rounded-2xl p-12 text-white mb-8 shadow-xl">
        <h1 className="text-5xl font-bold mb-4">Bienvenido a SecureDev Dashboard</h1>
        <p className="text-xl text-indigo-100 mb-6">
          Plataforma educativa para escribir código más seguro mediante análisis defensivo
        </p>
        <div className="flex gap-4">
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-6 py-4">
            <div className="text-3xl font-bold">OWASP Top 10</div>
            <div className="text-sm">Vulnerabilidades cubiertas</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-6 py-4">
            <div className="text-3xl font-bold">OSV.dev</div>
            <div className="text-sm">Base de datos de vulnerabilidades</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="bg-white rounded-xl p-6 shadow-lg border border-indigo-100">
          <div className="flex items-center gap-3 mb-4">
            <BookOpen className="w-8 h-8 text-indigo-600" />
            <h2 className="text-2xl font-bold text-gray-800">Módulo Educativo</h2>
          </div>
          <p className="text-gray-600 mb-4">
            Aprende sobre las vulnerabilidades más críticas con ejemplos de código vulnerable y seguro.
          </p>
          <ul className="space-y-2 text-sm text-gray-600">
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>Explicaciones simples y claras</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>Ejemplos de código real</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>Soluciones y mitigaciones</span>
            </li>
          </ul>
        </div>

        <div className="bg-white rounded-xl p-6 shadow-lg border border-purple-100">
          <div className="flex items-center gap-3 mb-4">
            <Search className="w-8 h-8 text-purple-600" />
            <h2 className="text-2xl font-bold text-gray-800">Escáner de Dependencias</h2>
          </div>
          <p className="text-gray-600 mb-4">
            Analiza tu archivo package.json para detectar vulnerabilidades conocidas en tus dependencias.
          </p>
          <ul className="space-y-2 text-sm text-gray-600">
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>Escaneo en tiempo real con OSV.dev</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>Reporte detallado de severidad</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>Enlaces a CVE y reportes</span>
            </li>
          </ul>
        </div>
      </div>

      <div className="bg-amber-50 border-l-4 border-amber-500 rounded-lg p-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-6 h-6 text-amber-600 flex-shrink-0 mt-1" />
          <div>
            <h3 className="text-lg font-bold text-amber-900 mb-2">Aviso Ético</h3>
            <p className="text-sm text-amber-800">
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

// Tarjeta de vulnerabilidad
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
      className="bg-white rounded-xl p-6 shadow-lg hover:shadow-xl transition-all border border-gray-200 text-left w-full group"
    >
      <div className="flex items-start justify-between mb-3">
        <h3 className="text-lg font-bold text-gray-800 group-hover:text-indigo-600 transition-colors">
          {vuln.name}
        </h3>
        <span className={`px-3 py-1 rounded-full text-xs font-bold text-white bg-gradient-to-r ${severityColors[vuln.severity]}`}>
          {vuln.severity.toUpperCase()}
        </span>
      </div>
      <p className="text-sm text-gray-600">{vuln.description}</p>
    </button>
  );
};

// Página de detalle de vulnerabilidad
const VulnerabilityDetail = ({ vuln, onBack }) => {
  const [activeTab, setActiveTab] = useState('whatIs');

  const tabs = [
    { id: 'whatIs', label: '¿Qué es?', icon: BookOpen },
    { id: 'vulnerable', label: 'Código Vulnerable', icon: XCircle },
    { id: 'secure', label: 'Código Seguro', icon: CheckCircle }
  ];

  return (
    <div className="max-w-6xl mx-auto">
      <button
        onClick={onBack}
        className="mb-6 flex items-center gap-2 text-indigo-600 hover:text-indigo-800 font-medium"
      >
        ← Volver a la lista
      </button>

      <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-8 text-white">
          <h1 className="text-4xl font-bold mb-3">{vuln.name}</h1>
          <p className="text-lg text-indigo-100">{vuln.description}</p>
        </div>

        <div className="border-b border-gray-200">
          <div className="flex">
            {tabs.map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'bg-white text-indigo-600 border-b-2 border-indigo-600'
                      : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="p-8">
          {activeTab === 'whatIs' && (
            <div className="prose max-w-none">
              <p className="text-lg text-gray-700 leading-relaxed">{vuln.whatIs}</p>
            </div>
          )}

          {activeTab === 'vulnerable' && (
            <div>
              <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-4 rounded">
                <div className="flex items-center gap-2 text-red-800 font-bold mb-2">
                  <XCircle className="w-5 h-5" />
                  Código Vulnerable - NO usar en producción
                </div>
              </div>
              <pre className="bg-gray-900 text-gray-100 p-6 rounded-lg overflow-x-auto">
                <code>{vuln.vulnerableCode}</code>
              </pre>
            </div>
          )}

          {activeTab === 'secure' && (
            <div>
              <div className="bg-green-50 border-l-4 border-green-500 p-4 mb-4 rounded">
                <div className="flex items-center gap-2 text-green-800 font-bold mb-2">
                  <CheckCircle className="w-5 h-5" />
                  Código Seguro - Implementación recomendada
                </div>
              </div>
              <pre className="bg-gray-900 text-gray-100 p-6 rounded-lg overflow-x-auto">
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
    <div className="max-w-6xl mx-auto">
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-gray-800 mb-3">Módulo Educativo</h1>
        <p className="text-lg text-gray-600">
          Aprende sobre las vulnerabilidades más críticas del OWASP Top 10 con ejemplos prácticos
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
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

// Componente Dropzone
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
      className={`border-3 border-dashed rounded-2xl p-12 text-center transition-all ${
        isDragging
          ? 'border-indigo-600 bg-indigo-50'
          : 'border-gray-300 bg-white hover:border-indigo-400 hover:bg-gray-50'
      }`}
    >
      <FileJson className="w-20 h-20 mx-auto mb-4 text-indigo-600" />
      <h3 className="text-2xl font-bold text-gray-800 mb-2">
        Arrastra tu archivo package.json aquí
      </h3>
      <p className="text-gray-600 mb-6">o haz clic para seleccionar un archivo</p>
      <label className="inline-block">
        <input
          type="file"
          accept=".json"
          onChange={handleFileInput}
          className="hidden"
        />
        <span className="bg-indigo-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors cursor-pointer inline-flex items-center gap-2">
          <Upload className="w-5 h-5" />
          Seleccionar archivo
        </span>
      </label>
    </div>
  );
};

// Tabla de resultados
const ResultsTable = ({ results }) => {
  const getSeverityColor = (severity) => {
    if (!severity) return 'bg-gray-100 text-gray-800';
    const sev = severity.toLowerCase();
    if (sev.includes('critical')) return 'bg-red-100 text-red-800';
    if (sev.includes('high')) return 'bg-orange-100 text-orange-800';
    if (sev.includes('medium')) return 'bg-yellow-100 text-yellow-800';
    return 'bg-blue-100 text-blue-800';
  };

  return (
    <div className="bg-white rounded-xl shadow-lg overflow-hidden">
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-6 text-white">
        <h2 className="text-2xl font-bold mb-3">Resultados del Escaneo</h2>
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-4">
            <div className="text-3xl font-bold">{results.summary.total}</div>
            <div className="text-sm">Paquetes analizados</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-4">
            <div className="text-3xl font-bold">{results.summary.vulnerable}</div>
            <div className="text-sm">Con vulnerabilidades</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-4">
            <div className="text-3xl font-bold">{results.summary.safe}</div>
            <div className="text-sm">Seguros</div>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-700">Estado</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-700">Paquete</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-700">Versión</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-700">Vulnerabilidades</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-700">Severidad</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-700">Detalles</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {results.packages.map((pkg, idx) => (
              <tr key={idx} className="hover:bg-gray-50 transition-colors">
                <td className="px-6 py-4">
                  {pkg.status === 'vulnerable' && (
                    <div className="flex items-center gap-2 text-red-600">
                      <XCircle className="w-5 h-5" />
                      <span className="font-medium">Vulnerable</span>
                    </div>
                  )}
                  {pkg.status === 'safe' && (
                    <div className="flex items-center gap-2 text-green-600">
                      <CheckCircle className="w-5 h-5" />
                      <span className="font-medium">Seguro</span>
                    </div>
                  )}
                  {pkg.status === 'error' && (
                    <div className="flex items-center gap-2 text-gray-600">
                      <AlertTriangle className="w-5 h-5" />
                      <span className="font-medium">Error</span>
                    </div>
                  )}
                </td>
                <td className="px-6 py-4 font-mono text-sm">{pkg.package}</td>
                <td className="px-6 py-4 font-mono text-sm text-gray-600">{pkg.version}</td>
                <td className="px-6 py-4">
                  {pkg.vulnerabilities.length > 0 ? (
                    <span className="font-bold text-red-600">{pkg.vulnerabilities.length}</span>
                  ) : (
                    <span className="text-gray-400">0</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  {pkg.vulnerabilities.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {pkg.vulnerabilities.slice(0, 3).map((vuln, vidx) => (
                        <span
                          key={vidx}
                          className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(
                            vuln.severity?.[0]?.score || vuln.database_specific?.severity
                          )}`}
                        >
                          {vuln.severity?.[0]?.score || vuln.database_specific?.severity || 'N/A'}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-400">-</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  {pkg.vulnerabilities.length > 0 && (
                    <div className="flex flex-col gap-1">
                      {pkg.vulnerabilities.slice(0, 2).map((vuln, vidx) => (
                        <a
                          key={vidx}
                          href={vuln.references?.[0]?.url || vuln.database_specific?.url || '#'}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-indigo-600 hover:text-indigo-800 text-sm"
                        >
                          <ExternalLink className="w-4 h-4" />
                          <span className="font-mono">{vuln.id || 'Ver más'}</span>
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
    <div className="max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-gray-800 mb-3">Escáner de Dependencias</h1>
        <p className="text-lg text-gray-600">
          Analiza tu archivo package.json para detectar vulnerabilidades conocidas usando OSV.dev
        </p>
      </div>

      {!results && !loading && (
        <>
          <FileDropzone onFileDrop={handleFileDrop} />
          
          <div className="mt-8 bg-blue-50 border border-blue-200 rounded-xl p-6">
            <h3 className="text-lg font-bold text-blue-900 mb-3 flex items-center gap-2">
              <Code className="w-5 h-5" />
              Cómo usar el escáner
            </h3>
            <ol className="space-y-2 text-blue-800">
              <li className="flex items-start gap-2">
                <span className="font-bold">1.</span>
                <span>Localiza el archivo <code className="bg-blue-100 px-2 py-1 rounded">package.json</code> de tu proyecto Node.js</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-bold">2.</span>
                <span>Arrastra el archivo a la zona de arriba o haz clic para seleccionarlo</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-bold">3.</span>
                <span>Espera mientras consultamos la base de datos de OSV.dev</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-bold">4.</span>
                <span>Revisa los resultados y toma acción sobre las vulnerabilidades encontradas</span>
              </li>
            </ol>
          </div>
        </>
      )}

      {loading && (
        <div className="bg-white rounded-xl p-12 text-center shadow-lg">
          <Loader className="w-16 h-16 mx-auto mb-4 text-indigo-600 animate-spin" />
          <h3 className="text-2xl font-bold text-gray-800 mb-2">Escaneando dependencias...</h3>
          <p className="text-gray-600">Consultando la base de datos de OSV.dev</p>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-6">
          <div className="flex items-center gap-3 text-red-800">
            <XCircle className="w-6 h-6" />
            <div>
              <h3 className="font-bold">Error al escanear</h3>
              <p>{error}</p>
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
              className="bg-indigo-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors"
            >
              Escanear otro archivo
            </button>
          </div>

          {results.summary.vulnerable > 0 && (
            <div className="mt-6 bg-amber-50 border border-amber-200 rounded-xl p-6">
              <h3 className="text-lg font-bold text-amber-900 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Recomendaciones
              </h3>
              <ul className="space-y-2 text-amber-800">
                <li className="flex items-start gap-2">
                  <span>•</span>
                  <span>Actualiza los paquetes vulnerables a versiones que no contengan las vulnerabilidades reportadas</span>
                </li>
                <li className="flex items-start gap-2">
                  <span>•</span>
                  <span>Si no hay versión actualizada, considera usar un paquete alternativo</span>
                </li>
                <li className="flex items-start gap-2">
                  <span>•</span>
                  <span>Ejecuta <code className="bg-amber-100 px-2 py-1 rounded">npm audit fix</code> para intentar arreglar automáticamente</span>
                </li>
                <li className="flex items-start gap-2">
                  <span>•</span>
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

// Componente principal
const App = () => {
  const [currentPage, setCurrentPage] = useState('home');

  return (
    <div className="min-h-screen bg-gray-50">
      <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />
      
      <div className="ml-64 p-8">
        {currentPage === 'home' && <HomePage />}
        {currentPage === 'education' && <EducationPage />}
        {currentPage === 'scanner' && <ScannerPage />}
      </div>
    </div>
  );
};

export default App;
