import React, { useState, useCallback, useEffect } from 'react';
import { Shield, BookOpen, Search, AlertTriangle, CheckCircle, XCircle, Upload, Loader, ExternalLink, Lock, Code, FileJson, Menu, X, Award, Target, TrendingUp, Brain, Play, RotateCcw, Trophy, Star, Book, Lightbulb, GraduationCap, Zap, ChevronRight, ChevronLeft, CheckSquare, XSquare, Eye } from 'lucide-react';

// ========================
// DATOS EDUCATIVOS EXPANDIDOS
// ========================
const vulnerabilitiesData = [
  {
    id: 'broken-access-control',
    name: 'Broken Access Control',
    severity: 'critical',
    description: 'Falla en la implementación de restricciones sobre lo que los usuarios autenticados pueden hacer.',
    whatIs: 'El control de acceso roto permite a los atacantes acceder a funcionalidades o datos para los que no tienen permisos. Esto puede incluir acceder a cuentas de otros usuarios, modificar datos, o ejecutar funciones administrativas.',
    impact: 'Puede resultar en acceso no autorizado a información sensible, modificación de datos, o ejecución de funciones privilegiadas.',
    realWorldExample: 'En 2021, una vulnerabilidad de control de acceso en una plataforma permitió a los usuarios ver datos personales de otros 40 millones de usuarios simplemente modificando un parámetro en la URL.',
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
});`,
    mitigations: [
      'Implementar control de acceso basado en roles (RBAC)',
      'Denegar por defecto y permitir explícitamente',
      'Validar permisos en cada solicitud',
      'Registrar y alertar sobre intentos de acceso no autorizados',
      'Implementar pruebas automatizadas de control de acceso'
    ],
    resources: [
      { title: 'OWASP Access Control Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html' },
      { title: 'NIST Access Control Guidelines', url: 'https://csrc.nist.gov/projects/access-control' }
    ]
  },
  {
    id: 'cryptographic-failures',
    name: 'Cryptographic Failures',
    severity: 'critical',
    description: 'Fallas relacionadas con la criptografía que conducen a la exposición de datos sensibles.',
    whatIs: 'Los fallos criptográficos incluyen almacenar datos sensibles en texto plano, usar algoritmos débiles, o implementar incorrectamente la criptografía. Esto puede exponer contraseñas, números de tarjetas de crédito, y otros datos personales.',
    impact: 'Exposición de datos sensibles como contraseñas, información financiera, datos de salud, o secretos comerciales.',
    realWorldExample: 'En 2019, una filtración masiva expuso contraseñas en texto plano de millones de usuarios porque no estaban correctamente hasheadas.',
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
}`,
    mitigations: [
      'Usar algoritmos de hash modernos (bcrypt, Argon2, scrypt)',
      'Implementar salt único para cada contraseña',
      'Usar HTTPS/TLS para todas las comunicaciones',
      'Nunca almacenar datos sensibles en texto plano',
      'Implementar rotación de claves criptográficas'
    ],
    resources: [
      { title: 'OWASP Cryptographic Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html' },
      { title: 'NIST Cryptographic Standards', url: 'https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines' }
    ]
  },
  {
    id: 'injection',
    name: 'Injection (SQL, NoSQL, Command)',
    severity: 'critical',
    description: 'Envío de datos no confiables a un intérprete como parte de un comando o consulta.',
    whatIs: 'Las vulnerabilidades de inyección ocurren cuando datos no validados son enviados a un intérprete. SQL Injection es la más común, permitiendo al atacante ejecutar comandos SQL arbitrarios en la base de datos.',
    impact: 'Puede resultar en acceso completo a la base de datos, modificación o eliminación de datos, y en algunos casos, ejecución de comandos en el servidor.',
    realWorldExample: 'Un ataque de SQL Injection en 2015 comprometió 157 millones de registros de usuarios, incluyendo emails y contraseñas.',
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
});`,
    mitigations: [
      'Usar consultas parametrizadas (prepared statements)',
      'Utilizar ORMs que saniticen las entradas',
      'Validar y sanitizar todas las entradas del usuario',
      'Implementar el principio de menor privilegio en la base de datos',
      'Usar procedimientos almacenados cuando sea apropiado'
    ],
    resources: [
      { title: 'OWASP SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
      { title: 'PortSwigger SQL Injection', url: 'https://portswigger.net/web-security/sql-injection' }
    ]
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    description: 'Permite a atacantes inyectar scripts maliciosos en páginas web vistas por otros usuarios.',
    whatIs: 'XSS ocurre cuando una aplicación incluye datos no validados en una página web sin escapar adecuadamente. Los atacantes pueden robar cookies de sesión, redirigir usuarios, o modificar el contenido de la página.',
    impact: 'Robo de sesiones, robo de credenciales, defacement de sitios web, distribución de malware.',
    realWorldExample: 'En 2018, British Airways sufrió un ataque XSS que comprometió los datos de pago de 380,000 clientes.',
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
const clean = DOMPurify.sanitize(comment.text);`,
    mitigations: [
      'Escapar todas las salidas de datos no confiables',
      'Usar Content Security Policy (CSP)',
      'Validar y sanitizar entradas',
      'Usar frameworks con protección XSS incorporada',
      'Implementar HTTPOnly y Secure flags en cookies'
    ],
    resources: [
      { title: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
      { title: 'PortSwigger XSS', url: 'https://portswigger.net/web-security/cross-site-scripting' }
    ]
  },
  {
    id: 'insecure-design',
    name: 'Insecure Design',
    severity: 'high',
    description: 'Fallas en el diseño y arquitectura de la aplicación que no pueden arreglarse solo con implementación.',
    whatIs: 'El diseño inseguro representa fallas en la lógica de negocio y arquitectura. Por ejemplo, un sistema de recuperación de contraseña que permite enumerar usuarios válidos, o un proceso de pago que permite modificar precios.',
    impact: 'Puede resultar en bypass de autenticación, manipulación de lógica de negocio, o acceso no autorizado a funcionalidades.',
    realWorldExample: 'Múltiples aplicaciones bancarias han sido explotadas debido a fallas de diseño que permitían transferir fondos sin validación adecuada.',
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
});`,
    mitigations: [
      'Realizar modelado de amenazas durante el diseño',
      'Implementar controles de seguridad desde el inicio',
      'Usar patrones de diseño seguros',
      'Realizar revisiones de seguridad en la fase de diseño',
      'Implementar defense in depth'
    ],
    resources: [
      { title: 'OWASP Secure Design Principles', url: 'https://owasp.org/www-project-developer-guide/draft/design/' },
      { title: 'Threat Modeling', url: 'https://owasp.org/www-community/Threat_Modeling' }
    ]
  },
  {
    id: 'security-misconfiguration',
    name: 'Security Misconfiguration',
    severity: 'high',
    description: 'Configuraciones de seguridad incorrectas, incompletas o con valores por defecto.',
    whatIs: 'Las configuraciones incorrectas incluyen mostrar stack traces detallados en producción, tener servicios no utilizados habilitados, usar credenciales por defecto, o tener permisos mal configurados.',
    impact: 'Puede exponer información sensible, proporcionar vectores de ataque adicionales, o permitir acceso no autorizado.',
    realWorldExample: 'En 2017, la filtración de Equifax fue parcialmente causada por una configuración incorrecta que dejó expuesta información de 147 millones de personas.',
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
}`,
    mitigations: [
      'Usar configuraciones seguras por defecto',
      'Mantener software actualizado',
      'Deshabilitar características y servicios no utilizados',
      'Implementar headers de seguridad (Helmet.js)',
      'Realizar auditorías de configuración regularmente'
    ],
    resources: [
      { title: 'OWASP Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
      { title: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' }
    ]
  },
  {
    id: 'vulnerable-components',
    name: 'Vulnerable and Outdated Components',
    severity: 'high',
    description: 'Uso de componentes con vulnerabilidades conocidas, sin parches, o no soportados.',
    whatIs: 'Usar bibliotecas y frameworks con vulnerabilidades conocidas es extremadamente común. Los atacantes buscan activamente aplicaciones que usen versiones vulnerables de componentes populares.',
    impact: 'Puede resultar en compromiso completo de la aplicación, robo de datos, o ejecución de código remoto.',
    realWorldExample: 'La vulnerabilidad Log4Shell en 2021 afectó a millones de aplicaciones Java debido a una vulnerabilidad en una biblioteca de logging ampliamente utilizada.',
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
// 4. Revisa el changelog antes de actualizar`,
    mitigations: [
      'Mantener inventario de componentes y versiones',
      'Monitorear bases de datos de vulnerabilidades',
      'Usar herramientas de análisis de dependencias',
      'Actualizar regularmente y probar después de actualizar',
      'Eliminar dependencias no utilizadas'
    ],
    resources: [
      { title: 'OWASP Dependency Check', url: 'https://owasp.org/www-project-dependency-check/' },
      { title: 'Snyk', url: 'https://snyk.io/' }
    ]
  },
  {
    id: 'auth-failures',
    name: 'Identification and Authentication Failures',
    severity: 'critical',
    description: 'Fallas en la confirmación de identidad, autenticación, o manejo de sesiones.',
    whatIs: 'Las fallas de autenticación permiten a atacantes comprometer contraseñas, claves, tokens de sesión, o explotar otras fallas para asumir temporalmente o permanentemente la identidad de otros usuarios.',
    impact: 'Acceso no autorizado a cuentas, robo de identidad, fraude, y acceso a datos sensibles.',
    realWorldExample: 'Millones de cuentas han sido comprometidas debido a ataques de credential stuffing y falta de protección contra fuerza bruta.',
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
});`,
    mitigations: [
      'Implementar autenticación multi-factor (MFA)',
      'Usar rate limiting y CAPTCHAs',
      'Implementar gestión segura de sesiones',
      'Usar contraseñas fuertes y hashing adecuado',
      'Implementar timeout de sesión'
    ],
    resources: [
      { title: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
      { title: 'NIST Digital Identity Guidelines', url: 'https://pages.nist.gov/800-63-3/' }
    ]
  }
];

// ========================
// DATOS DE QUIZ
// ========================
const quizQuestions = [
  {
    id: 1,
    vulnerabilityId: 'broken-access-control',
    question: '¿Cuál de las siguientes prácticas previene Broken Access Control?',
    options: [
      'Permitir que los usuarios accedan a cualquier recurso por defecto',
      'Validar permisos solo en el frontend',
      'Implementar control de acceso basado en roles y validar en cada solicitud',
      'Confiar en los parámetros enviados por el cliente'
    ],
    correctAnswer: 2,
    explanation: 'El control de acceso debe implementarse en el servidor, validando permisos en cada solicitud y siguiendo el principio de menor privilegio.'
  },
  {
    id: 2,
    vulnerabilityId: 'cryptographic-failures',
    question: '¿Cuál es la forma MÁS segura de almacenar contraseñas?',
    options: [
      'Usar MD5 hash',
      'Almacenar en texto plano con cifrado reversible',
      'Usar bcrypt con salt único para cada contraseña',
      'Usar SHA-1 hash'
    ],
    correctAnswer: 2,
    explanation: 'Bcrypt es un algoritmo diseñado específicamente para hashear contraseñas, que incluye salt automático y es resistente a ataques de fuerza bruta.'
  },
  {
    id: 3,
    vulnerabilityId: 'injection',
    question: '¿Cómo se previene SQL Injection?',
    options: [
      'Validando la entrada solo en el frontend',
      'Usando consultas parametrizadas (prepared statements)',
      'Escapando comillas simples manualmente',
      'Confiando en la validación del navegador'
    ],
    correctAnswer: 1,
    explanation: 'Las consultas parametrizadas separan el código SQL de los datos, previniendo que los datos de entrada sean interpretados como comandos SQL.'
  },
  {
    id: 4,
    vulnerabilityId: 'xss',
    question: '¿Cuál de estos métodos NO previene XSS?',
    options: [
      'Escapar todas las salidas HTML',
      'Usar Content Security Policy (CSP)',
      'Validar solo las entradas numéricas',
      'Usar textContent en lugar de innerHTML'
    ],
    correctAnswer: 2,
    explanation: 'Validar solo entradas numéricas no es suficiente. Se debe escapar/sanitizar todas las salidas y usar CSP como defensa adicional.'
  },
  {
    id: 5,
    vulnerabilityId: 'auth-failures',
    question: '¿Qué característica mejora significativamente la seguridad de autenticación?',
    options: [
      'Permitir contraseñas cortas para facilitar el acceso',
      'Almacenar sesiones sin timeout',
      'Implementar autenticación multi-factor (2FA)',
      'Mostrar si el usuario o contraseña es incorrecto'
    ],
    correctAnswer: 2,
    explanation: 'La autenticación multi-factor agrega una capa adicional de seguridad que hace mucho más difícil el acceso no autorizado, incluso si la contraseña es comprometida.'
  },
  {
    id: 6,
    vulnerabilityId: 'vulnerable-components',
    question: '¿Cuál es la mejor práctica para gestionar dependencias?',
    options: [
      'Nunca actualizar para mantener estabilidad',
      'Ejecutar npm audit regularmente y mantener dependencias actualizadas',
      'Usar siempre la última versión sin probar',
      'Ignorar las advertencias de seguridad'
    ],
    correctAnswer: 1,
    explanation: 'Es crucial mantener las dependencias actualizadas, usar herramientas de auditoría regularmente, y probar las actualizaciones antes de desplegarlas.'
  },
  {
    id: 7,
    vulnerabilityId: 'security-misconfiguration',
    question: '¿Qué NO debe hacerse en un ambiente de producción?',
    options: [
      'Usar Helmet.js para headers de seguridad',
      'Implementar rate limiting',
      'Mostrar stack traces completos en mensajes de error',
      'Deshabilitar características no utilizadas'
    ],
    correctAnswer: 2,
    explanation: 'Los stack traces pueden revelar información sensible sobre la estructura de la aplicación, rutas de archivos, y versiones de software, que pueden ser útiles para atacantes.'
  },
  {
    id: 8,
    vulnerabilityId: 'insecure-design',
    question: '¿Qué caracteriza a un diseño seguro?',
    options: [
      'Confiar en que los usuarios no intentarán hacer cosas maliciosas',
      'Implementar seguridad solo después del desarrollo',
      'Realizar modelado de amenazas e implementar defense in depth desde el diseño',
      'Validar solo en el frontend para mejor UX'
    ],
    correctAnswer: 2,
    explanation: 'Un diseño seguro requiere considerar la seguridad desde el inicio, realizar modelado de amenazas, e implementar múltiples capas de defensa.'
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
// HOOK PARA PROGRESO DEL USUARIO
// ========================
const useProgress = () => {
  const [progress, setProgress] = useState(() => {
    const saved = localStorage.getItem('securedev-progress');
    return saved ? JSON.parse(saved) : {
      completedVulnerabilities: [],
      quizScores: {},
      totalTimeSpent: 0,
      achievements: []
    };
  });

  useEffect(() => {
    localStorage.setItem('securedev-progress', JSON.stringify(progress));
  }, [progress]);

  const markVulnerabilityCompleted = (vulnId) => {
    setProgress(prev => ({
      ...prev,
      completedVulnerabilities: [...new Set([...prev.completedVulnerabilities, vulnId])]
    }));
  };

  const saveQuizScore = (score, total) => {
    setProgress(prev => ({
      ...prev,
      quizScores: {
        ...prev.quizScores,
        [Date.now()]: { score, total, percentage: (score / total) * 100 }
      }
    }));
  };

  const addAchievement = (achievement) => {
    setProgress(prev => ({
      ...prev,
      achievements: [...new Set([...prev.achievements, achievement])]
    }));
  };

  const resetProgress = () => {
    setProgress({
      completedVulnerabilities: [],
      quizScores: {},
      totalTimeSpent: 0,
      achievements: []
    });
  };

  return {
    progress,
    markVulnerabilityCompleted,
    saveQuizScore,
    addAchievement,
    resetProgress
  };
};

// ========================
// COMPONENTES
// ========================

// Sidebar mejorado con logo de Cybervaltorix
const Sidebar = ({ currentPage, setCurrentPage, isOpen, setIsOpen }) => {
  const menuItems = [
    { id: 'home', icon: Shield, label: 'Inicio' },
    { id: 'education', icon: BookOpen, label: 'Educación' },
    { id: 'quiz', icon: Brain, label: 'Quiz' },
    { id: 'lab', icon: Code, label: 'Laboratorio' },
    { id: 'scanner', icon: Search, label: 'Escáner' },
    { id: 'progress', icon: Trophy, label: 'Progreso' }
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
          {/* Logo de Cybervaltorix */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex flex-col items-center w-full">
              <img 
                src="https://cybervaltorix.com/wp-content/uploads/2025/09/Logo-Valtorix-1.png" 
                alt="Cybervaltorix" 
                className="h-12 mb-3 object-contain"
              />
              <div className="text-center">
                <h1 className="text-xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
                  SecureDev
                </h1>
                <p className="text-xs text-indigo-300">Dashboard v2.0</p>
              </div>
            </div>
            <button 
              onClick={() => setIsOpen(false)}
              className="lg:hidden absolute top-4 right-4 text-white/70 hover:text-white"
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
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all group ${
                    currentPage === item.id
                      ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-lg border border-white/20'
                      : 'text-indigo-100 hover:bg-white/10 hover:backdrop-blur-sm'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${currentPage === item.id ? 'animate-pulse' : 'group-hover:scale-110 transition-transform'}`} />
                  <span className="font-medium">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
        
        <div className="absolute bottom-0 left-0 right-0 p-6 border-t border-white/10 bg-black/20 backdrop-blur-sm">
          <div className="flex items-center gap-2 text-xs text-indigo-300">
            <Lock className="w-4 h-4" />
            <span>Powered by Cybervaltorix</span>
          </div>
        </div>
      </div>
    </>
  );
};

// Botón de menú móvil con animación
const MobileMenuButton = ({ onClick }) => (
  <button
    onClick={onClick}
    className="lg:hidden fixed top-4 left-4 z-30 p-3 bg-gradient-to-r from-indigo-600 to-purple-600 backdrop-blur-xl rounded-lg border border-white/10 shadow-lg hover:scale-105 transition-transform"
  >
    <Menu className="w-6 h-6 text-white" />
  </button>
);

// Página de inicio mejorada
const HomePage = () => {
  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6 animate-fade-in">
      {/* Hero Section con gradiente animado */}
      <div className="relative bg-gradient-to-br from-indigo-600 via-purple-600 to-pink-600 rounded-2xl p-6 sm:p-12 text-white mb-8 shadow-2xl overflow-hidden">
        <div className="absolute inset-0 bg-grid-white/10 [mask-image:linear-gradient(0deg,transparent,white)]"></div>
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-12 h-12 animate-pulse" />
            <div>
              <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold">
                Bienvenido a SecureDev Dashboard
              </h1>
              <p className="text-sm text-indigo-100">Powered by Cybervaltorix</p>
            </div>
          </div>
          <p className="text-lg sm:text-xl text-indigo-100 mb-6">
            Plataforma educativa profesional para dominar la seguridad en desarrollo de software
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 sm:px-6 py-4 border border-white/20 hover:bg-white/30 transition-all cursor-pointer">
              <BookOpen className="w-8 h-8 mb-2" />
              <div className="text-2xl sm:text-3xl font-bold">8</div>
              <div className="text-xs sm:text-sm">Vulnerabilidades OWASP</div>
            </div>
            <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 sm:px-6 py-4 border border-white/20 hover:bg-white/30 transition-all cursor-pointer">
              <Brain className="w-8 h-8 mb-2" />
              <div className="text-2xl sm:text-3xl font-bold">Quiz</div>
              <div className="text-xs sm:text-sm">Interactivo</div>
            </div>
            <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 sm:px-6 py-4 border border-white/20 hover:bg-white/30 transition-all cursor-pointer">
              <Search className="w-8 h-8 mb-2" />
              <div className="text-2xl sm:text-3xl font-bold">OSV.dev</div>
              <div className="text-xs sm:text-sm">Escáner integrado</div>
            </div>
          </div>
        </div>
      </div>

      {/* Features Grid mejorado */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {[
          {
            icon: BookOpen,
            title: 'Módulo Educativo',
            description: 'Aprende sobre las vulnerabilidades más críticas con ejemplos reales y código',
            color: 'from-indigo-500 to-purple-500',
            features: ['Explicaciones detalladas', 'Ejemplos del mundo real', 'Código vulnerable y seguro', 'Recursos adicionales']
          },
          {
            icon: Brain,
            title: 'Quiz Interactivo',
            description: 'Evalúa tu conocimiento con preguntas diseñadas por expertos',
            color: 'from-purple-500 to-pink-500',
            features: ['8 preguntas OWASP', 'Explicaciones detalladas', 'Sistema de puntuación', 'Retroalimentación inmediata']
          },
          {
            icon: Code,
            title: 'Laboratorio de Práctica',
            description: 'Practica escribiendo código seguro en un entorno controlado',
            color: 'from-pink-500 to-red-500',
            features: ['Editor de código', 'Ejercicios prácticos', 'Validación automática', 'Hints y soluciones']
          },
          {
            icon: Search,
            title: 'Escáner de Dependencias',
            description: 'Analiza y detecta vulnerabilidades en tus proyectos',
            color: 'from-blue-500 to-cyan-500',
            features: ['OSV.dev integrado', 'Análisis en tiempo real', 'Reportes detallados', 'Recomendaciones']
          }
        ].map((feature, index) => (
          <div 
            key={index}
            className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-6 shadow-xl border border-white/10 hover:border-white/20 transition-all hover:scale-[1.02] cursor-pointer group"
          >
            <div className={`inline-flex items-center justify-center w-12 h-12 rounded-lg bg-gradient-to-r ${feature.color} mb-4 group-hover:scale-110 transition-transform`}>
              <feature.icon className="w-6 h-6 text-white" />
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-3">{feature.title}</h2>
            <p className="text-gray-300 mb-4 text-sm sm:text-base">{feature.description}</p>
            <ul className="space-y-2">
              {feature.features.map((item, i) => (
                <li key={i} className="flex items-center gap-2 text-sm text-gray-300">
                  <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {/* Quick Stats */}
      <div className="bg-gradient-to-r from-slate-900/60 to-slate-800/60 backdrop-blur-xl rounded-xl p-6 border border-white/10 mb-8">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <Zap className="w-6 h-6 text-yellow-400" />
          Inicio Rápido
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center gap-3 p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-all cursor-pointer">
            <div className="w-10 h-10 rounded-full bg-indigo-500/20 flex items-center justify-center">
              <span className="text-indigo-400 font-bold">1</span>
            </div>
            <div>
              <div className="text-white font-medium text-sm">Explora las vulnerabilidades</div>
              <div className="text-gray-400 text-xs">Módulo educativo</div>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-all cursor-pointer">
            <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center">
              <span className="text-purple-400 font-bold">2</span>
            </div>
            <div>
              <div className="text-white font-medium text-sm">Toma el quiz</div>
              <div className="text-gray-400 text-xs">Evalúa tu conocimiento</div>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-all cursor-pointer">
            <div className="w-10 h-10 rounded-full bg-pink-500/20 flex items-center justify-center">
              <span className="text-pink-400 font-bold">3</span>
            </div>
            <div>
              <div className="text-white font-medium text-sm">Escanea tu proyecto</div>
              <div className="text-gray-400 text-xs">Encuentra vulnerabilidades</div>
            </div>
          </div>
        </div>
      </div>

      {/* Warning Banner mejorado */}
      <div className="bg-gradient-to-r from-amber-900/30 to-orange-900/30 backdrop-blur-xl border border-amber-500/30 rounded-xl p-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0 mt-1 animate-pulse" />
          <div>
            <h3 className="text-lg font-bold text-amber-200 mb-2">Aviso Ético y Legal</h3>
            <p className="text-sm text-amber-100 mb-3">
              Esta herramienta está diseñada estrictamente para fines educativos y defensivos. 
              Solo debe usarse para analizar proyectos de los que se es propietario o se tiene 
              permiso explícito para evaluar.
            </p>
            <div className="flex items-center gap-2 text-xs text-amber-200">
              <Lock className="w-4 h-4" />
              <span>El uso no autorizado de técnicas de seguridad es ilegal</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Tarjeta de vulnerabilidad mejorada
const VulnerabilityCard = ({ vuln, onClick, isCompleted }) => {
  const severityColors = {
    critical: 'from-red-500 to-red-600',
    high: 'from-orange-500 to-orange-600',
    medium: 'from-yellow-500 to-yellow-600',
    low: 'from-blue-500 to-blue-600'
  };

  return (
    <button
      onClick={onClick}
      className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-4 sm:p-6 shadow-xl hover:shadow-2xl transition-all border border-white/10 hover:border-white/20 text-left w-full group relative overflow-hidden"
    >
      {isCompleted && (
        <div className="absolute top-4 right-4">
          <CheckCircle className="w-6 h-6 text-green-400" />
        </div>
      )}
      <div className="flex flex-col sm:flex-row items-start justify-between gap-3 mb-3">
        <h3 className="text-base sm:text-lg font-bold text-white group-hover:text-indigo-400 transition-colors pr-8">
          {vuln.name}
        </h3>
        <span className={`px-3 py-1 rounded-full text-xs font-bold text-white bg-gradient-to-r ${severityColors[vuln.severity]} flex-shrink-0`}>
          {vuln.severity.toUpperCase()}
        </span>
      </div>
      <p className="text-sm text-gray-300 mb-3">{vuln.description}</p>
      <div className="flex items-center gap-2 text-xs text-indigo-400">
        <ChevronRight className="w-4 h-4" />
        <span>Explorar detalles</span>
      </div>
    </button>
  );
};

// Página de detalle de vulnerabilidad mejorada
const VulnerabilityDetail = ({ vuln, onBack, markAsCompleted }) => {
  const [activeTab, setActiveTab] = useState('whatIs');

  const tabs = [
    { id: 'whatIs', label: '¿Qué es?', icon: BookOpen },
    { id: 'impact', label: 'Impacto', icon: AlertTriangle },
    { id: 'vulnerable', label: 'Vulnerable', icon: XCircle },
    { id: 'secure', label: 'Seguro', icon: CheckCircle },
    { id: 'resources', label: 'Recursos', icon: Book }
  ];

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6 animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-indigo-400 hover:text-indigo-300 font-medium text-sm sm:text-base transition-all hover:gap-3"
        >
          <ChevronLeft className="w-5 h-5" />
          Volver a la lista
        </button>
        <button
          onClick={markAsCompleted}
          className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium transition-all"
        >
          <CheckCircle className="w-4 h-4" />
          Marcar como completado
        </button>
      </div>

      <div className="bg-slate-900/40 backdrop-blur-xl rounded-2xl shadow-2xl overflow-hidden border border-white/10">
        {/* Header con gradiente */}
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-6 sm:p-8 text-white">
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold mb-3">{vuln.name}</h1>
          <p className="text-base sm:text-lg text-indigo-100">{vuln.description}</p>
        </div>

        {/* Tabs mejorados */}
        <div className="border-b border-white/10 bg-slate-900/60">
          <div className="flex overflow-x-auto">
            {tabs.map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 sm:px-6 py-3 sm:py-4 font-medium transition-all whitespace-nowrap text-sm sm:text-base ${
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

        {/* Content mejorado */}
        <div className="p-4 sm:p-8">
          {activeTab === 'whatIs' && (
            <div className="prose prose-invert max-w-none">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <Lightbulb className="w-6 h-6 text-yellow-400" />
                Explicación Detallada
              </h3>
              <p className="text-base sm:text-lg text-gray-200 leading-relaxed mb-6">{vuln.whatIs}</p>
              
              {vuln.realWorldExample && (
                <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4 mb-4">
                  <h4 className="text-lg font-bold text-blue-300 mb-2 flex items-center gap-2">
                    <Star className="w-5 h-5" />
                    Ejemplo del Mundo Real
                  </h4>
                  <p className="text-blue-100 text-sm">{vuln.realWorldExample}</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'impact' && (
            <div>
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="w-6 h-6 text-orange-400" />
                Impacto y Consecuencias
              </h3>
              <p className="text-base sm:text-lg text-gray-200 leading-relaxed mb-6">{vuln.impact}</p>
              
              {vuln.mitigations && (
                <div>
                  <h4 className="text-lg font-bold text-white mb-3">Medidas de Mitigación</h4>
                  <ul className="space-y-3">
                    {vuln.mitigations.map((mitigation, index) => (
                      <li key={index} className="flex items-start gap-3 bg-slate-800/40 p-4 rounded-lg">
                        <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-200">{mitigation}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {activeTab === 'vulnerable' && (
            <div>
              <div className="bg-red-900/20 backdrop-blur-sm border border-red-500/30 p-4 mb-4 rounded-lg">
                <div className="flex items-center gap-2 text-red-300 font-bold mb-2 text-sm sm:text-base">
                  <XCircle className="w-5 h-5 flex-shrink-0" />
                  Código Vulnerable - NO usar en producción
                </div>
                <p className="text-red-200 text-sm">Este código tiene fallas de seguridad críticas. Estúdialo para identificar los problemas.</p>
              </div>
              <pre className="bg-black/80 backdrop-blur-sm text-gray-100 p-4 sm:p-6 rounded-lg overflow-x-auto text-xs sm:text-sm border border-red-500/30">
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
                <p className="text-green-200 text-sm">Este código implementa las mejores prácticas de seguridad.</p>
              </div>
              <pre className="bg-black/80 backdrop-blur-sm text-gray-100 p-4 sm:p-6 rounded-lg overflow-x-auto text-xs sm:text-sm border border-green-500/30">
                <code>{vuln.secureCode}</code>
              </pre>
            </div>
          )}

          {activeTab === 'resources' && vuln.resources && (
            <div>
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <Book className="w-6 h-6 text-purple-400" />
                Recursos Adicionales
              </h3>
              <div className="space-y-3">
                {vuln.resources.map((resource, index) => (
                  <a
                    key={index}
                    href={resource.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-4 bg-slate-800/40 hover:bg-slate-800/60 rounded-lg border border-white/10 hover:border-indigo-500/50 transition-all group"
                  >
                    <div className="flex items-center gap-3">
                      <ExternalLink className="w-5 h-5 text-indigo-400 group-hover:text-indigo-300" />
                      <span className="text-white font-medium">{resource.title}</span>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400 group-hover:text-indigo-400 transition-colors" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Página de educación mejorada
const EducationPage = ({ progress, markVulnerabilityCompleted }) => {
  const [selectedVuln, setSelectedVuln] = useState(null);

  if (selectedVuln) {
    return (
      <VulnerabilityDetail
        vuln={selectedVuln}
        onBack={() => setSelectedVuln(null)}
        markAsCompleted={() => {
          markVulnerabilityCompleted(selectedVuln.id);
          setSelectedVuln(null);
        }}
      />
    );
  }

  const completionPercentage = (progress.completedVulnerabilities.length / vulnerabilitiesData.length) * 100;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6 animate-fade-in">
      <div className="mb-8">
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3 flex items-center gap-3">
          <GraduationCap className="w-10 h-10 text-indigo-400" />
          Módulo Educativo
        </h1>
        <p className="text-base sm:text-lg text-gray-300 mb-4">
          Aprende sobre las vulnerabilidades más críticas del OWASP Top 10 con ejemplos prácticos
        </p>
        
        {/* Barra de progreso */}
        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-4 border border-white/10">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-300">Tu Progreso</span>
            <span className="text-sm font-bold text-indigo-400">{Math.round(completionPercentage)}%</span>
          </div>
          <div className="w-full bg-slate-700/50 rounded-full h-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-indigo-500 to-purple-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${completionPercentage}%` }}
            />
          </div>
          <div className="mt-2 text-xs text-gray-400">
            {progress.completedVulnerabilities.length} de {vulnerabilitiesData.length} vulnerabilidades completadas
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        {vulnerabilitiesData.map(vuln => (
          <VulnerabilityCard
            key={vuln.id}
            vuln={vuln}
            onClick={() => setSelectedVuln(vuln)}
            isCompleted={progress.completedVulnerabilities.includes(vuln.id)}
          />
        ))}
      </div>
    </div>
  );
};

// Página de Quiz mejorada y totalmente responsiva
const QuizPage = ({ saveQuizScore }) => {
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState({});
  const [showResults, setShowResults] = useState(false);
  const [score, setScore] = useState(0);

  const handleAnswer = (questionId, answerIndex) => {
    setSelectedAnswers(prev => ({
      ...prev,
      [questionId]: answerIndex
    }));
  };

  const handleNext = () => {
    if (currentQuestion < quizQuestions.length - 1) {
      setCurrentQuestion(currentQuestion + 1);
    } else {
      calculateScore();
    }
  };

  const handlePrevious = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(currentQuestion - 1);
    }
  };

  const calculateScore = () => {
    let correctAnswers = 0;
    quizQuestions.forEach(question => {
      if (selectedAnswers[question.id] === question.correctAnswer) {
        correctAnswers++;
      }
    });
    setScore(correctAnswers);
    saveQuizScore(correctAnswers, quizQuestions.length);
    setShowResults(true);
  };

  const resetQuiz = () => {
    setCurrentQuestion(0);
    setSelectedAnswers({});
    setShowResults(false);
    setScore(0);
  };

  if (showResults) {
    const percentage = (score / quizQuestions.length) * 100;
    const passed = percentage >= 70;

    return (
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 animate-fade-in">
        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl sm:rounded-2xl shadow-2xl overflow-hidden border border-white/10">
          <div className={`p-4 sm:p-6 lg:p-8 text-white ${passed ? 'bg-gradient-to-r from-green-600 to-emerald-600' : 'bg-gradient-to-r from-orange-600 to-red-600'}`}>
            <div className="flex items-center justify-center mb-3 sm:mb-4">
              {passed ? (
                <Trophy className="w-12 h-12 sm:w-16 sm:h-16 text-yellow-300 animate-bounce" />
              ) : (
                <Target className="w-12 h-12 sm:w-16 sm:h-16" />
              )}
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-center mb-2 sm:mb-3">
              {passed ? '¡Felicitaciones!' : 'Sigue Practicando'}
            </h1>
            <p className="text-sm sm:text-base lg:text-lg text-center">
              {passed 
                ? 'Has demostrado un excelente conocimiento en seguridad' 
                : 'La práctica hace al maestro. Revisa los temas y vuelve a intentarlo'}
            </p>
          </div>

          <div className="p-4 sm:p-6 lg:p-8">
            <div className="text-center mb-6 sm:mb-8">
              <div className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white mb-2">{score}/{quizQuestions.length}</div>
              <div className="text-xl sm:text-2xl text-gray-300">{Math.round(percentage)}% Correcto</div>
            </div>

            <div className="space-y-3 sm:space-y-4 mb-6 sm:mb-8 max-h-[60vh] overflow-y-auto pr-2">
              {quizQuestions.map((question) => {
                const userAnswer = selectedAnswers[question.id];
                const isCorrect = userAnswer === question.correctAnswer;

                return (
                  <div key={question.id} className="bg-slate-800/40 rounded-lg p-3 sm:p-4 border border-white/10">
                    <div className="flex items-start gap-2 sm:gap-3 mb-2 sm:mb-3">
                      {isCorrect ? (
                        <CheckSquare className="w-5 h-5 sm:w-6 sm:h-6 text-green-400 flex-shrink-0 mt-0.5 sm:mt-1" />
                      ) : (
                        <XSquare className="w-5 h-5 sm:w-6 sm:h-6 text-red-400 flex-shrink-0 mt-0.5 sm:mt-1" />
                      )}
                      <div className="flex-1 min-w-0">
                        <h3 className="text-sm sm:text-base text-white font-medium mb-2 break-words">{question.question}</h3>
                        <div className="text-xs sm:text-sm space-y-1 sm:space-y-2">
                          <div className={`${isCorrect ? 'text-green-400' : 'text-red-400'} break-words`}>
                            <span className="font-semibold">Tu respuesta: </span>
                            {question.options[userAnswer]}
                          </div>
                          {!isCorrect && (
                            <div className="text-green-400 break-words">
                              <span className="font-semibold">Correcta: </span>
                              {question.options[question.correctAnswer]}
                            </div>
                          )}
                          <div className="text-gray-400 mt-2 p-2 sm:p-3 bg-slate-900/60 rounded text-xs sm:text-sm break-words">
                            <strong className="text-gray-300">Explicación: </strong>{question.explanation}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex justify-center">
              <button
                onClick={resetQuiz}
                className="flex items-center gap-2 px-4 sm:px-6 py-2 sm:py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-all text-sm sm:text-base"
              >
                <RotateCcw className="w-4 h-4 sm:w-5 sm:h-5" />
                Intentar de Nuevo
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const question = quizQuestions[currentQuestion];
  const progress = ((currentQuestion + 1) / quizQuestions.length) * 100;

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 animate-fade-in">
      <div className="mb-4 sm:mb-6">
        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white mb-2 sm:mb-3 flex items-center gap-2 sm:gap-3">
          <Brain className="w-8 h-8 sm:w-10 sm:h-10 text-purple-400" />
          Quiz de Seguridad
        </h1>
        <p className="text-sm sm:text-base lg:text-lg text-gray-300">
          Pon a prueba tu conocimiento sobre vulnerabilidades de seguridad
        </p>
      </div>

      {/* Barra de progreso del quiz */}
      <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-3 sm:p-4 mb-4 sm:mb-6 border border-white/10">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs sm:text-sm text-gray-300">
            Pregunta <span className="font-bold">{currentQuestion + 1}</span> de <span className="font-bold">{quizQuestions.length}</span>
          </span>
          <span className="text-xs sm:text-sm font-bold text-purple-400">{Math.round(progress)}%</span>
        </div>
        <div className="w-full bg-slate-700/50 rounded-full h-2 overflow-hidden">
          <div 
            className="bg-gradient-to-r from-purple-500 to-pink-500 h-full rounded-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Pregunta */}
      <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl sm:rounded-2xl shadow-2xl overflow-hidden border border-white/10">
        <div className="bg-gradient-to-r from-purple-600 to-pink-600 p-4 sm:p-6 lg:p-8 text-white">
          <h2 className="text-base sm:text-lg lg:text-2xl font-bold break-words">{question.question}</h2>
        </div>

        <div className="p-4 sm:p-6 lg:p-8">
          <div className="space-y-2 sm:space-y-3 mb-6 sm:mb-8">
            {question.options.map((option, index) => (
              <button
                key={index}
                onClick={() => handleAnswer(question.id, index)}
                className={`w-full text-left p-3 sm:p-4 rounded-lg border-2 transition-all ${
                  selectedAnswers[question.id] === index
                    ? 'border-purple-500 bg-purple-500/20 text-white'
                    : 'border-white/10 bg-slate-800/40 text-gray-300 hover:border-purple-500/50 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-start gap-2 sm:gap-3">
                  <div className={`w-5 h-5 sm:w-6 sm:h-6 rounded-full border-2 flex items-center justify-center flex-shrink-0 mt-0.5 ${
                    selectedAnswers[question.id] === index
                      ? 'border-purple-500 bg-purple-500'
                      : 'border-gray-500'
                  }`}>
                    {selectedAnswers[question.id] === index && (
                      <CheckCircle className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                    )}
                  </div>
                  <span className="flex-1 text-sm sm:text-base break-words">{option}</span>
                </div>
              </button>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <button
              onClick={handlePrevious}
              disabled={currentQuestion === 0}
              className={`flex items-center justify-center gap-2 px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium transition-all text-sm sm:text-base ${
                currentQuestion === 0
                  ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                  : 'bg-slate-700 text-white hover:bg-slate-600'
              }`}
            >
              <ChevronLeft className="w-4 h-4 sm:w-5 sm:h-5" />
              <span>Anterior</span>
            </button>

            <button
              onClick={handleNext}
              disabled={selectedAnswers[question.id] === undefined}
              className={`flex items-center justify-center gap-2 px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium transition-all text-sm sm:text-base ${
                selectedAnswers[question.id] === undefined
                  ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                  : currentQuestion === quizQuestions.length - 1
                  ? 'bg-gradient-to-r from-green-600 to-emerald-600 text-white hover:from-green-700 hover:to-emerald-700'
                  : 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:from-purple-700 hover:to-pink-700'
              }`}
            >
              <span>{currentQuestion === quizQuestions.length - 1 ? 'Finalizar' : 'Siguiente'}</span>
              {currentQuestion === quizQuestions.length - 1 ? (
                <Target className="w-4 h-4 sm:w-5 sm:h-5" />
              ) : (
                <ChevronRight className="w-4 h-4 sm:w-5 sm:h-5" />
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Página de Laboratorio (nuevo) - Corregido y totalmente responsivo
const LabPage = () => {
  const [activeExercise, setActiveExercise] = useState(null);
  const [userCode, setUserCode] = useState('');
  const [feedback, setFeedback] = useState(null);
  const [showSolution, setShowSolution] = useState(false);

  const exercises = [
    {
      id: 1,
      title: 'Prevenir SQL Injection',
      description: 'Corrige este código vulnerable a SQL Injection usando consultas parametrizadas',
      vulnerableCode: `// Código vulnerable
app.post('/login', async (req, res) => {
  const query = \`SELECT * FROM users WHERE username = '\${req.body.username}'\`;
  const user = await db.query(query);
});`,
      hint: 'Usa consultas parametrizadas con ? como placeholders',
      solution: `// Código seguro
app.post('/login', async (req, res) => {
  const query = 'SELECT * FROM users WHERE username = ?';
  const user = await db.query(query, [req.body.username]);
});`,
      keywords: ['?', 'parametrizada', 'query']
    },
    {
      id: 2,
      title: 'Implementar Control de Acceso',
      description: 'Agrega validación de permisos para que los usuarios solo accedan a sus propios recursos',
      vulnerableCode: `// Código sin validación
app.get('/api/user/:id/profile', async (req, res) => {
  const profile = await getUserProfile(req.params.id);
  res.json(profile);
});`,
      hint: 'Compara el ID solicitado con el ID del usuario autenticado',
      solution: `// Código seguro
app.get('/api/user/:id/profile', authenticateUser, async (req, res) => {
  if (req.params.id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  const profile = await getUserProfile(req.params.id);
  res.json(profile);
});`,
      keywords: ['req.user.id', 'req.params.id', '!==', '403']
    },
    {
      id: 3,
      title: 'Prevenir XSS',
      description: 'Corrige este código para prevenir ataques de Cross-Site Scripting',
      vulnerableCode: `// Código vulnerable
function displayComment(comment) {
  document.getElementById('comments').innerHTML += 
    '<div>' + comment.text + '</div>';
}`,
      hint: 'Usa textContent en lugar de innerHTML, o createElement',
      solution: `// Código seguro
function displayComment(comment) {
  const div = document.createElement('div');
  div.textContent = comment.text;
  document.getElementById('comments').appendChild(div);
}`,
      keywords: ['textContent', 'createElement', 'appendChild']
    }
  ];

  const checkSolution = () => {
    if (!activeExercise) return;
    
    const exercise = exercises.find(e => e.id === activeExercise);
    if (!exercise) return;
    
    // Validación mejorada - busca palabras clave
    const hasKeywords = exercise.keywords.some(keyword => 
      userCode.toLowerCase().includes(keyword.toLowerCase())
    );
    
    const isCorrect = hasKeywords;
    
    setFeedback({
      correct: isCorrect,
      message: isCorrect 
        ? '¡Excelente! Has implementado correctamente la solución de seguridad.' 
        : 'Intenta de nuevo. Revisa el hint para obtener ayuda. Asegúrate de usar las técnicas correctas de seguridad.'
    });

    if (isCorrect) {
      setShowSolution(false);
    }
  };

  const handleReset = () => {
    const exercise = exercises.find(e => e.id === activeExercise);
    if (exercise) {
      setUserCode(exercise.vulnerableCode);
      setFeedback(null);
      setShowSolution(false);
    }
  };

  const toggleSolution = () => {
    const exercise = exercises.find(e => e.id === activeExercise);
    if (exercise) {
      if (!showSolution) {
        setUserCode(exercise.solution);
        setShowSolution(true);
        setFeedback(null);
      } else {
        setUserCode(exercise.vulnerableCode);
        setShowSolution(false);
        setFeedback(null);
      }
    }
  };

  if (!activeExercise) {
    return (
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 animate-fade-in">
        <div className="mb-6 sm:mb-8">
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white mb-2 sm:mb-3 flex items-center gap-2 sm:gap-3">
            <Code className="w-8 h-8 sm:w-10 sm:h-10 text-pink-400" />
            Laboratorio de Práctica
          </h1>
          <p className="text-sm sm:text-base lg:text-lg text-gray-300">
            Practica escribiendo código seguro en un entorno controlado
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:gap-6">
          {exercises.map((exercise) => (
            <div
              key={exercise.id}
              className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-4 sm:p-6 shadow-xl border border-white/10 hover:border-white/20 transition-all cursor-pointer group hover:scale-[1.02]"
              onClick={() => {
                setActiveExercise(exercise.id);
                setUserCode(exercise.vulnerableCode);
                setFeedback(null);
                setShowSolution(false);
              }}
            >
              <div className="flex items-start justify-between gap-3 mb-3">
                <h3 className="text-lg sm:text-xl font-bold text-white group-hover:text-indigo-400 transition-colors">
                  {exercise.title}
                </h3>
                <div className="bg-pink-500/20 px-2 sm:px-3 py-1 rounded-full">
                  <span className="text-xs sm:text-sm font-bold text-pink-400">#{exercise.id}</span>
                </div>
              </div>
              <p className="text-sm sm:text-base text-gray-300 mb-4">{exercise.description}</p>
              <div className="flex items-center gap-2 text-sm text-pink-400 group-hover:gap-3 transition-all">
                <Play className="w-4 h-4" />
                <span className="font-medium">Iniciar ejercicio</span>
              </div>
            </div>
          ))}
        </div>

        {/* Info adicional */}
        <div className="mt-6 sm:mt-8 bg-gradient-to-r from-indigo-900/20 to-purple-900/20 backdrop-blur-xl border border-indigo-500/30 rounded-xl p-4 sm:p-6">
          <h3 className="text-base sm:text-lg font-bold text-indigo-200 mb-3 flex items-center gap-2">
            <Lightbulb className="w-5 h-5" />
            Consejos para el Laboratorio
          </h3>
          <ul className="space-y-2 text-xs sm:text-sm text-indigo-100">
            <li className="flex items-start gap-2">
              <CheckCircle className="w-4 h-4 text-indigo-400 flex-shrink-0 mt-0.5" />
              <span>Lee cuidadosamente la descripción del ejercicio</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle className="w-4 h-4 text-indigo-400 flex-shrink-0 mt-0.5" />
              <span>Usa las pistas si te atascas</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle className="w-4 h-4 text-indigo-400 flex-shrink-0 mt-0.5" />
              <span>Intenta resolverlo antes de ver la solución</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle className="w-4 h-4 text-indigo-400 flex-shrink-0 mt-0.5" />
              <span>Experimenta con diferentes enfoques</span>
            </li>
          </ul>
        </div>
      </div>
    );
  }

  const exercise = exercises.find(e => e.id === activeExercise);
  if (!exercise) return null;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 animate-fade-in">
      <button
        onClick={() => {
          setActiveExercise(null);
          setUserCode('');
          setFeedback(null);
          setShowSolution(false);
        }}
        className="mb-4 sm:mb-6 flex items-center gap-2 text-indigo-400 hover:text-indigo-300 font-medium text-sm sm:text-base transition-all hover:gap-3"
      >
        <ChevronLeft className="w-4 h-4 sm:w-5 sm:h-5" />
        Volver a ejercicios
      </button>

      <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl sm:rounded-2xl shadow-2xl overflow-hidden border border-white/10 mb-4 sm:mb-6">
        {/* Header */}
        <div className="bg-gradient-to-r from-pink-600 to-purple-600 p-4 sm:p-6 text-white">
          <div className="flex items-start justify-between gap-3 mb-2">
            <h1 className="text-xl sm:text-2xl font-bold">{exercise.title}</h1>
            <div className="bg-white/20 px-2 sm:px-3 py-1 rounded-full flex-shrink-0">
              <span className="text-xs sm:text-sm font-bold">#{exercise.id}</span>
            </div>
          </div>
          <p className="text-sm sm:text-base text-pink-100">{exercise.description}</p>
        </div>

        {/* Content */}
        <div className="p-4 sm:p-6">
          {/* Pista */}
          <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-3 sm:p-4 mb-4">
            <div className="flex items-start gap-2 sm:gap-3">
              <Lightbulb className="w-4 h-4 sm:w-5 sm:h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="text-blue-300 font-bold mb-1 text-sm sm:text-base">💡 Pista</div>
                <div className="text-blue-100 text-xs sm:text-sm">{exercise.hint}</div>
              </div>
            </div>
          </div>

          {/* Editor de código */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <label className="block text-white font-medium text-sm sm:text-base">
                {showSolution ? '✅ Solución:' : '📝 Tu Código:'}
              </label>
              {showSolution && (
                <span className="text-xs sm:text-sm text-green-400 font-medium">
                  Código Seguro
                </span>
              )}
            </div>
            <textarea
              value={userCode}
              onChange={(e) => setUserCode(e.target.value)}
              className="w-full h-48 sm:h-64 lg:h-80 bg-black/60 text-gray-100 p-3 sm:p-4 rounded-lg font-mono text-xs sm:text-sm border border-white/10 focus:border-indigo-500 focus:outline-none resize-none"
              placeholder="Escribe tu solución aquí..."
              spellCheck="false"
            />
          </div>

          {/* Feedback */}
          {feedback && (
            <div className={`p-3 sm:p-4 rounded-lg mb-4 animate-fade-in ${
              feedback.correct 
                ? 'bg-green-900/20 border border-green-500/30' 
                : 'bg-orange-900/20 border border-orange-500/30'
            }`}>
              <div className="flex items-start gap-2 sm:gap-3">
                {feedback.correct ? (
                  <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
                )}
                <span className={`text-sm sm:text-base ${feedback.correct ? 'text-green-300' : 'text-orange-300'}`}>
                  {feedback.message}
                </span>
              </div>
            </div>
          )}

          {/* Botones de acción */}
          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
            <button
              onClick={checkSolution}
              disabled={showSolution}
              className={`flex items-center justify-center gap-2 px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium transition-all text-sm sm:text-base ${
                showSolution
                  ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white'
              }`}
            >
              <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5" />
              Verificar Solución
            </button>
            
            <button
              onClick={toggleSolution}
              className="flex items-center justify-center gap-2 px-4 sm:px-6 py-2 sm:py-3 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white rounded-lg font-medium transition-all text-sm sm:text-base"
            >
              <Eye className="w-4 h-4 sm:w-5 sm:h-5" />
              {showSolution ? 'Ocultar Solución' : 'Ver Solución'}
            </button>

            <button
              onClick={handleReset}
              className="flex items-center justify-center gap-2 px-4 sm:px-6 py-2 sm:py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-medium transition-all text-sm sm:text-base"
            >
              <RotateCcw className="w-4 h-4 sm:w-5 sm:h-5" />
              Reiniciar
            </button>
          </div>
        </div>
      </div>

      {/* Tips adicionales */}
      <div className="bg-gradient-to-r from-purple-900/20 to-pink-900/20 backdrop-blur-xl border border-purple-500/30 rounded-xl p-4 sm:p-6">
        <h3 className="text-base sm:text-lg font-bold text-purple-200 mb-3 flex items-center gap-2">
          <Star className="w-5 h-5" />
          Tips de Seguridad
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="bg-purple-900/20 rounded-lg p-3">
            <h4 className="text-sm font-bold text-purple-300 mb-1">✅ Hacer</h4>
            <ul className="text-xs text-purple-100 space-y-1">
              <li>• Validar todas las entradas</li>
              <li>• Usar consultas parametrizadas</li>
              <li>• Implementar autenticación</li>
            </ul>
          </div>
          <div className="bg-red-900/20 rounded-lg p-3">
            <h4 className="text-sm font-bold text-red-300 mb-1">❌ Evitar</h4>
            <ul className="text-xs text-red-100 space-y-1">
              <li>• Concatenar strings en SQL</li>
              <li>• Confiar en datos del cliente</li>
              <li>• Usar innerHTML sin sanitizar</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

// Página de Progreso (nuevo)
const ProgressPage = ({ progress, resetProgress }) => {
  const completionPercentage = (progress.completedVulnerabilities.length / vulnerabilitiesData.length) * 100;
  const quizScoresArray = Object.values(progress.quizScores);
  const averageQuizScore = quizScoresArray.length > 0
    ? quizScoresArray.reduce((sum, score) => sum + score.percentage, 0) / quizScoresArray.length
    : 0;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6 animate-fade-in">
      <div className="mb-8">
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3 flex items-center gap-3">
          <Trophy className="w-10 h-10 text-yellow-400" />
          Tu Progreso
        </h1>
        <p className="text-base sm:text-lg text-gray-300">
          Revisa tu avance en el aprendizaje de seguridad
        </p>
      </div>

      {/* Estadísticas principales */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-gradient-to-br from-indigo-600 to-purple-600 rounded-xl p-6 text-white shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <BookOpen className="w-10 h-10" />
            <span className="text-4xl font-bold">{Math.round(completionPercentage)}%</span>
          </div>
          <h3 className="text-lg font-bold mb-1">Vulnerabilidades</h3>
          <p className="text-sm text-indigo-100">
            {progress.completedVulnerabilities.length} de {vulnerabilitiesData.length} completadas
          </p>
        </div>

        <div className="bg-gradient-to-br from-purple-600 to-pink-600 rounded-xl p-6 text-white shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <Brain className="w-10 h-10" />
            <span className="text-4xl font-bold">{Math.round(averageQuizScore)}%</span>
          </div>
          <h3 className="text-lg font-bold mb-1">Quiz</h3>
          <p className="text-sm text-purple-100">
            Promedio de {quizScoresArray.length} intentos
          </p>
        </div>

        <div className="bg-gradient-to-br from-pink-600 to-red-600 rounded-xl p-6 text-white shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <Award className="w-10 h-10" />
            <span className="text-4xl font-bold">{progress.achievements.length}</span>
          </div>
          <h3 className="text-lg font-bold mb-1">Logros</h3>
          <p className="text-sm text-pink-100">
            Insignias desbloqueadas
          </p>
        </div>
      </div>

      {/* Vulnerabilidades completadas */}
      <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-6 mb-8 border border-white/10">
        <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
          <CheckCircle className="w-6 h-6 text-green-400" />
          Vulnerabilidades Completadas
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {vulnerabilitiesData.map((vuln) => {
            const isCompleted = progress.completedVulnerabilities.includes(vuln.id);
            return (
              <div
                key={vuln.id}
                className={`p-4 rounded-lg border ${
                  isCompleted
                    ? 'bg-green-900/20 border-green-500/30'
                    : 'bg-slate-800/40 border-white/10'
                }`}
              >
                <div className="flex items-center gap-3">
                  {isCompleted ? (
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                  ) : (
                    <XCircle className="w-5 h-5 text-gray-500 flex-shrink-0" />
                  )}
                  <span className={isCompleted ? 'text-green-300' : 'text-gray-400'}>
                    {vuln.name}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Historial de quiz */}
      {quizScoresArray.length > 0 && (
        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-6 mb-8 border border-white/10">
          <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-6 h-6 text-purple-400" />
            Historial de Quiz
          </h2>
          <div className="space-y-3">
            {quizScoresArray.slice(-5).reverse().map((score, index) => (
              <div key={index} className="flex items-center justify-between p-4 bg-slate-800/40 rounded-lg">
                <div>
                  <div className="text-white font-medium">{score.score} / {score.total} correctas</div>
                  <div className="text-sm text-gray-400">
                    {new Date(parseInt(Object.keys(progress.quizScores)[quizScoresArray.length - 1 - index])).toLocaleDateString()}
                  </div>
                </div>
                <div className="text-2xl font-bold text-purple-400">{Math.round(score.percentage)}%</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Botón de reset */}
      <div className="flex justify-center">
        <button
          onClick={() => {
            if (confirm('¿Estás seguro de que quieres resetear todo tu progreso?')) {
              resetProgress();
            }
          }}
          className="flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-all"
        >
          <RotateCcw className="w-5 h-5" />
          Resetear Progreso
        </button>
      </div>
    </div>
  );
};

// Dropzone mejorado
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
          ? 'border-indigo-400 bg-indigo-900/20 backdrop-blur-xl scale-105'
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
        <span className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium hover:from-indigo-700 hover:to-purple-700 transition-all cursor-pointer inline-flex items-center gap-2 text-sm sm:text-base">
          <Upload className="w-4 h-4 sm:w-5 sm:h-5" />
          Seleccionar archivo
        </span>
      </label>
    </div>
  );
};

// Tabla de resultados mejorada y totalmente responsiva
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
    <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl shadow-2xl overflow-hidden border border-white/10 animate-fade-in">
      {/* Header mejorado */}
      <div className="bg-gradient-to-r from-indigo-600/90 to-purple-600/90 backdrop-blur-xl p-4 sm:p-6 text-white border-b border-white/10">
        <h2 className="text-lg sm:text-xl lg:text-2xl font-bold mb-3 sm:mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 sm:w-6 sm:h-6" />
          Resultados del Escaneo
        </h2>
        <div className="grid grid-cols-3 gap-2 sm:gap-4">
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-2 sm:p-3 lg:p-4 border border-white/20 hover:scale-105 transition-transform">
            <div className="text-xl sm:text-2xl lg:text-3xl font-bold">{results.summary.total}</div>
            <div className="text-xs sm:text-sm">Paquetes</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-2 sm:p-3 lg:p-4 border border-white/20 hover:scale-105 transition-transform">
            <div className="text-xl sm:text-2xl lg:text-3xl font-bold text-red-300">{results.summary.vulnerable}</div>
            <div className="text-xs sm:text-sm">Vulnerables</div>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg p-2 sm:p-3 lg:p-4 border border-white/20 hover:scale-105 transition-transform">
            <div className="text-xl sm:text-2xl lg:text-3xl font-bold text-green-300">{results.summary.safe}</div>
            <div className="text-xs sm:text-sm">Seguros</div>
          </div>
        </div>
      </div>

      {/* Tabla responsiva - Vista móvil con cards */}
      <div className="block lg:hidden">
        <div className="divide-y divide-white/10">
          {results.packages.map((pkg, idx) => (
            <div key={idx} className="p-4 hover:bg-slate-800/40 transition-colors">
              {/* Estado */}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  {pkg.status === 'vulnerable' && (
                    <>
                      <XCircle className="w-5 h-5 text-red-400 animate-pulse flex-shrink-0" />
                      <span className="text-sm font-medium text-red-400">Vulnerable</span>
                    </>
                  )}
                  {pkg.status === 'safe' && (
                    <>
                      <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                      <span className="text-sm font-medium text-green-400">Seguro</span>
                    </>
                  )}
                  {pkg.status === 'error' && (
                    <>
                      <AlertTriangle className="w-5 h-5 text-gray-400 flex-shrink-0" />
                      <span className="text-sm font-medium text-gray-400">Error</span>
                    </>
                  )}
                </div>
                {pkg.vulnerabilities.length > 0 && (
                  <span className="bg-red-900/40 px-2 py-1 rounded text-xs font-bold text-red-300">
                    {pkg.vulnerabilities.length} Vulns
                  </span>
                )}
              </div>

              {/* Paquete y versión */}
              <div className="mb-3">
                <div className="font-mono text-sm text-white break-all mb-1">{pkg.package}</div>
                <div className="font-mono text-xs text-gray-400">v{pkg.version}</div>
              </div>

              {/* Severidad y detalles */}
              {pkg.vulnerabilities.length > 0 && (
                <div className="space-y-2">
                  <div className="flex flex-wrap gap-1">
                    {pkg.vulnerabilities.slice(0, 3).map((vuln, vidx) => (
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
                  <div className="flex flex-col gap-1">
                    {pkg.vulnerabilities.slice(0, 2).map((vuln, vidx) => (
                      <a
                        key={vidx}
                        href={vuln.references?.[0]?.url || vuln.database_specific?.url || '#'}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300 text-xs transition-all hover:gap-2"
                      >
                        <ExternalLink className="w-3 h-3 flex-shrink-0" />
                        <span className="font-mono truncate">{vuln.id || 'Ver más'}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Tabla desktop */}
      <div className="hidden lg:block overflow-x-auto">
        <table className="w-full">
          <thead className="bg-slate-900/60 backdrop-blur-sm border-b border-white/10">
            <tr>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-300">Estado</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-300">Paquete</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-300">Versión</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-300">Vulns</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-300">Severidad</th>
              <th className="px-6 py-4 text-left text-sm font-bold text-gray-300">Detalles</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {results.packages.map((pkg, idx) => (
              <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                <td className="px-6 py-4">
                  {pkg.status === 'vulnerable' && (
                    <div className="flex items-center gap-2 text-red-400">
                      <XCircle className="w-5 h-5 flex-shrink-0 animate-pulse" />
                      <span className="font-medium text-sm">Vulnerable</span>
                    </div>
                  )}
                  {pkg.status === 'safe' && (
                    <div className="flex items-center gap-2 text-green-400">
                      <CheckCircle className="w-5 h-5 flex-shrink-0" />
                      <span className="font-medium text-sm">Seguro</span>
                    </div>
                  )}
                  {pkg.status === 'error' && (
                    <div className="flex items-center gap-2 text-gray-400">
                      <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                      <span className="font-medium text-sm">Error</span>
                    </div>
                  )}
                </td>
                <td className="px-6 py-4">
                  <div className="font-mono text-sm text-white break-all">{pkg.package}</div>
                </td>
                <td className="px-6 py-4 font-mono text-sm text-gray-400">{pkg.version}</td>
                <td className="px-6 py-4">
                  {pkg.vulnerabilities.length > 0 ? (
                    <span className="font-bold text-red-400 text-base">{pkg.vulnerabilities.length}</span>
                  ) : (
                    <span className="text-gray-500 text-base">0</span>
                  )}
                </td>
                <td className="px-6 py-4">
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
                <td className="px-6 py-4">
                  {pkg.vulnerabilities.length > 0 && (
                    <div className="flex flex-col gap-1">
                      {pkg.vulnerabilities.slice(0, 2).map((vuln, vidx) => (
                        <a
                          key={vidx}
                          href={vuln.references?.[0]?.url || vuln.database_specific?.url || '#'}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300 text-sm transition-all hover:gap-2"
                        >
                          <ExternalLink className="w-4 h-4 flex-shrink-0" />
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

// Página de escáner mejorada
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
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 animate-fade-in">
      <div className="mb-8">
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3 flex items-center gap-3">
          <Search className="w-10 h-10 text-cyan-400" />
          Escáner de Dependencias
        </h1>
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
            <ol className="space-y-3 text-sm sm:text-base text-blue-100">
              {[
                'Localiza el archivo package.json de tu proyecto Node.js',
                'Arrastra el archivo a la zona de arriba o haz clic para seleccionarlo',
                'Espera mientras consultamos la base de datos de OSV.dev',
                'Revisa los resultados y toma acción sobre las vulnerabilidades encontradas'
              ].map((step, index) => (
                <li key={index} className="flex items-start gap-3 p-3 bg-blue-900/20 rounded-lg">
                  <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/30 flex items-center justify-center text-blue-200 font-bold text-sm">
                    {index + 1}
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        </>
      )}

      {loading && (
        <div className="bg-slate-900/40 backdrop-blur-xl rounded-xl p-8 sm:p-12 text-center shadow-2xl border border-white/10">
          <Loader className="w-12 h-12 sm:w-16 sm:h-16 mx-auto mb-4 text-indigo-400 animate-spin" />
          <h3 className="text-xl sm:text-2xl font-bold text-white mb-2">Escaneando dependencias...</h3>
          <p className="text-gray-300 text-sm sm:text-base">Consultando la base de datos de OSV.dev</p>
          <div className="mt-6 max-w-md mx-auto">
            <div className="w-full bg-slate-700/50 rounded-full h-2 overflow-hidden">
              <div className="bg-gradient-to-r from-indigo-500 to-purple-500 h-full rounded-full animate-pulse w-3/4"></div>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 backdrop-blur-xl border border-red-500/30 rounded-xl p-4 sm:p-6 animate-fade-in">
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
              className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium transition-all text-sm sm:text-base"
            >
              <RotateCcw className="w-5 h-5" />
              Escanear otro archivo
            </button>
          </div>

          {results.summary.vulnerable > 0 && (
            <div className="mt-6 bg-amber-900/20 backdrop-blur-xl border border-amber-500/30 rounded-xl p-4 sm:p-6 animate-fade-in">
              <h3 className="text-base sm:text-lg font-bold text-amber-200 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 animate-pulse" />
                Recomendaciones de Seguridad
              </h3>
              <ul className="space-y-3 text-sm sm:text-base text-amber-100">
                {[
                  'Actualiza los paquetes vulnerables a versiones que no contengan las vulnerabilidades reportadas',
                  'Si no hay versión actualizada, considera usar un paquete alternativo',
                  'Ejecuta npm audit fix para intentar arreglar automáticamente',
                  'Revisa los enlaces a CVE para entender el impacto de cada vulnerabilidad',
                  'Implementa una política de actualización regular de dependencias'
                ].map((rec, index) => (
                  <li key={index} className="flex items-start gap-3 p-3 bg-amber-900/20 rounded-lg">
                    <CheckCircle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// Componente principal mejorado
const App = () => {
  const [currentPage, setCurrentPage] = useState('home');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { progress, markVulnerabilityCompleted, saveQuizScore, addAchievement, resetProgress } = useProgress();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <style>{`
        @keyframes fade-in {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in {
          animation: fade-in 0.5s ease-out;
        }
        .bg-grid-white\/10 {
          background-image: linear-gradient(white 1px, transparent 1px), linear-gradient(90deg, white 1px, transparent 1px);
          background-size: 50px 50px;
          opacity: 0.1;
        }
      `}</style>
      
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
            {currentPage === 'education' && (
              <EducationPage 
                progress={progress}
                markVulnerabilityCompleted={markVulnerabilityCompleted}
              />
            )}
            {currentPage === 'quiz' && (
              <QuizPage saveQuizScore={saveQuizScore} />
            )}
            {currentPage === 'lab' && <LabPage />}
            {currentPage === 'scanner' && <ScannerPage />}
            {currentPage === 'progress' && (
              <ProgressPage 
                progress={progress}
                resetProgress={resetProgress}
              />
            )}
          </main>
        </div>
      </div>
    </div>
  );
};

export default App;
