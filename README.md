# 🛡️ SecureDev Dashboard v2.0

**Powered by [Cybervaltorix](https://cybervaltorix.com)**

Plataforma educativa profesional para dominar la seguridad en desarrollo de software. Aprende, practica y evalúa tus conocimientos sobre vulnerabilidades OWASP Top 10.

![SecureDev Dashboard](https://img.shields.io/badge/version-2.0-blue)
![React](https://img.shields.io/badge/React-18.2.0-61dafb)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Nuevas Características v2.0

### 🎨 Interfaz Mejorada
- **Logo de Cybervaltorix** integrado profesionalmente
- Diseño moderno con animaciones y transiciones suaves
- Interfaz totalmente responsive y optimizada
- Sistema de colores mejorado con gradientes atractivos
- Efectos glassmorphism y backdrop blur

### 📚 Módulo Educativo Expandido
- **8 vulnerabilidades OWASP** con contenido detallado
- Explicaciones más profundas con ejemplos del mundo real
- Recursos adicionales y enlaces a documentación oficial
- Sistema de progreso de aprendizaje
- Marcado de vulnerabilidades completadas

### 🧠 Quiz Interactivo
- **8 preguntas** diseñadas por expertos en seguridad
- Explicaciones detalladas de cada respuesta
- Sistema de puntuación y retroalimentación inmediata
- Historial de intentos
- Modo de revisión con respuestas correctas

### 🧪 Laboratorio de Práctica
- **Editor de código interactivo**
- Ejercicios prácticos de programación segura
- Sistema de hints y ayuda
- Validación automática de soluciones
- Posibilidad de ver la solución completa

### 📊 Dashboard de Progreso
- Seguimiento detallado de tu aprendizaje
- Estadísticas visuales de progreso
- Historial de quiz scores
- Sistema de achievements (en desarrollo)
- Opción de resetear progreso

### 🔍 Escáner OSV.dev Mejorado
- Interfaz más intuitiva
- Resultados con más detalles
- Recomendaciones de seguridad expandidas
- Mejor visualización de severidad
- Enlaces directos a CVEs

## 🚀 Instalación y Uso

### Requisitos Previos
- Node.js 16+ o npm
- Navegador web moderno

### Instalación Local

1. **Clona o descarga el proyecto**

2. **Instala las dependencias**:
   ```bash
   npm install
   ```

3. **Inicia el servidor de desarrollo**:
   ```bash
   npm run dev
   ```

4. **Abre tu navegador** en `http://localhost:5173`

## 🌐 Desplegar en Vercel

### Opción 1: Desde GitHub (Recomendado)

1. **Sube el proyecto a GitHub**

2. **Conecta con Vercel**:
   - Ve a [vercel.com](https://vercel.com)
   - Haz clic en "Add New Project"
   - Importa tu repositorio de GitHub
   - Vercel detectará automáticamente la configuración de Vite

3. **Deploy**:
   - Haz clic en "Deploy"
   - Tu aplicación estará lista en segundos

### Opción 2: Usando Vercel CLI

```bash
# Instala Vercel CLI
npm install -g vercel

# Despliega
vercel

# Para producción
vercel --prod
```

## 📖 Estructura del Proyecto

```
securedev-dashboard/
├── src/
│   ├── App.jsx          # Componente principal con todas las páginas
│   ├── main.jsx         # Punto de entrada
│   └── index.css        # Estilos globales
├── public/              # Archivos estáticos
├── index.html          # HTML principal
├── package.json        # Dependencias
├── vite.config.js      # Configuración de Vite
├── tailwind.config.js  # Configuración de Tailwind
└── postcss.config.js   # Configuración de PostCSS
```

## 🎯 Características Principales

### 1. Módulo Educativo
- **OWASP Top 10**: Broken Access Control, Cryptographic Failures, Injection, XSS, y más
- **Ejemplos Reales**: Casos de uso del mundo real
- **Código Vulnerable vs Seguro**: Comparación lado a lado
- **Mitigaciones**: Cómo prevenir cada vulnerabilidad
- **Recursos**: Enlaces a documentación oficial

### 2. Quiz Interactivo
- Evalúa tu conocimiento
- Preguntas basadas en escenarios reales
- Explicaciones detalladas
- Sistema de scoring
- Retroalimentación inmediata

### 3. Laboratorio
- Práctica de código seguro
- Ejercicios interactivos
- Sistema de hints
- Validación automática
- Soluciones completas

### 4. Escáner de Dependencias
- Integración con OSV.dev
- Análisis en tiempo real
- Reportes detallados
- Recomendaciones de seguridad
- Enlaces a CVEs

### 5. Dashboard de Progreso
- Seguimiento de aprendizaje
- Estadísticas visuales
- Historial completo
- Sistema de achievements
- Exportación de progreso (próximamente)

## 🔧 Tecnologías Utilizadas

- **React 18** - Framework de UI
- **Vite** - Build tool ultrarrápido
- **Tailwind CSS** - Framework de CSS utility-first
- **Lucide React** - Iconos modernos
- **OSV.dev API** - Base de datos de vulnerabilidades
- **LocalStorage** - Persistencia de progreso

## 🎨 Personalización

### Colores
Los colores principales se pueden modificar en `tailwind.config.js`:
- Indigo: Elementos principales
- Purple: Acentos secundarios
- Pink: Elementos de énfasis

### Logo
El logo de Cybervaltorix está integrado en el sidebar. Para cambiarlo, modifica la URL en `App.jsx`.

## 📱 Responsive Design

El dashboard está completamente optimizado para:
- 📱 Móviles (320px+)
- 📱 Tablets (768px+)
- 💻 Desktop (1024px+)
- 🖥️ Large Desktop (1280px+)

## ⚠️ Aviso Ético

Esta herramienta está diseñada estrictamente para fines educativos y defensivos. 

**Uso Autorizado Únicamente:**
- ✅ Análisis de tus propios proyectos
- ✅ Proyectos con permiso explícito
- ✅ Fines educativos y de capacitación
- ❌ Pruebas no autorizadas
- ❌ Acceso a sistemas sin permiso

**El uso no autorizado de técnicas de seguridad es ilegal.**

## 🤝 Créditos

- **Desarrollado por**: [Cybervaltorix](https://cybervaltorix.com)
- **OWASP Top 10**: [OWASP Foundation](https://owasp.org)
- **OSV.dev**: [Google OSV](https://osv.dev)
- **Iconos**: [Lucide](https://lucide.dev)

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo LICENSE para más detalles.

## 🔮 Roadmap

### Próximas Características
- [ ] Más ejercicios de laboratorio
- [ ] Sistema de achievements completo
- [ ] Modo oscuro/claro
- [ ] Exportación de reportes PDF
- [ ] Integración con más APIs de seguridad
- [ ] Soporte multi-idioma
- [ ] Modo offline
- [ ] Gamificación avanzada

## 📞 Soporte

- **Website**: [cybervaltorix.com](https://cybervaltorix.com)
- **Issues**: Reporta problemas en GitHub
- **Documentación**: README.md y código comentado

## 🌟 Contribuciones

Las contribuciones son bienvenidas. Por favor:
1. Fork el proyecto
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

---

**Hecho con ❤️ por [Cybervaltorix](https://cybervaltorix.com)**

*SecureDev Dashboard - Aprende seguridad escribiendo código más seguro*
