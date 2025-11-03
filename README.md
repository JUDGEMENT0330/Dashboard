# 🛡️ SecureDev Dashboard

Plataforma educativa para escribir código más seguro mediante análisis defensivo. Incluye un módulo educativo sobre vulnerabilidades OWASP Top 10 y un escáner de dependencias que utiliza la API de OSV.dev.

## 🚀 Características

- **Módulo Educativo**: Aprende sobre las 8 vulnerabilidades más críticas del OWASP Top 10 con ejemplos de código vulnerable y seguro
- **Escáner de Dependencias**: Analiza archivos package.json para detectar vulnerabilidades conocidas usando OSV.dev
- **Interfaz Moderna**: Diseño responsive con Tailwind CSS y componentes interactivos
- **100% Cliente**: No requiere backend, todo se ejecuta en el navegador

## 📋 Requisitos Previos

- Node.js 16+ o npm
- Cuenta en Vercel (gratis)

## 🛠️ Instalación Local

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

### Opción 1: Despliegue desde la CLI (Recomendado)

1. **Instala Vercel CLI globalmente** (si no lo tienes):
   ```bash
   npm install -g vercel
   ```

2. **Desde la carpeta del proyecto**, ejecuta:
   ```bash
   vercel
   ```

3. **Sigue las instrucciones**:
   - Presiona Enter para confirmar el proyecto
   - Selecciona tu cuenta/organización
   - Confirma el nombre del proyecto
   - Confirma la carpeta raíz (.)
   - **NO** sobrescribas la configuración

4. **Para desplegar a producción**:
   ```bash
   vercel --prod
   ```

### Opción 2: Despliegue desde GitHub

1. **Sube el código a GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/tu-usuario/securedev-dashboard.git
   git push -u origin main
   ```

2. **Ve a [vercel.com](https://vercel.com)**

3. **Haz clic en "Add New Project"**

4. **Importa tu repositorio de GitHub**

5. **Configura el proyecto**:
   - Framework Preset: Vite
   - Build Command: `npm run build` (ya configurado)
   - Output Directory: `dist` (ya configurado)
   - Install Command: `npm install` (ya configurado)

6. **Haz clic en "Deploy"**

### Opción 3: Despliegue Drag & Drop

1. **Construye el proyecto localmente**:
   ```bash
   npm run build
   ```

2. **Ve a [vercel.com/new](https://vercel.com/new)**

3. **Arrastra la carpeta `dist`** a la zona de despliegue

4. **Espera a que termine el despliegue**

## 📦 Scripts Disponibles

- `npm run dev` - Inicia el servidor de desarrollo
- `npm run build` - Construye la aplicación para producción
- `npm run preview` - Previsualiza el build de producción

## 🔧 Tecnologías Utilizadas

- **React 18** - Biblioteca de UI
- **Vite** - Build tool y dev server
- **Tailwind CSS** - Framework de CSS utility-first
- **Lucide React** - Iconos
- **OSV.dev API** - Base de datos de vulnerabilidades

## 📖 Uso

### Módulo Educativo

1. Navega a la sección "Educación"
2. Explora las diferentes vulnerabilidades del OWASP Top 10
3. Haz clic en cualquier vulnerabilidad para ver:
   - Explicación detallada
   - Código vulnerable (ejemplo de lo que NO hacer)
   - Código seguro (implementación recomendada)

### Escáner de Dependencias

1. Navega a la sección "Escáner"
2. Arrastra tu archivo `package.json` o haz clic para seleccionarlo
3. Espera mientras se escanean las dependencias
4. Revisa el reporte de vulnerabilidades
5. Sigue las recomendaciones para actualizar paquetes vulnerables

## ⚠️ Aviso Ético

Esta herramienta está diseñada estrictamente para fines educativos y defensivos. Solo debe usarse para analizar proyectos de los que se es propietario o se tiene permiso explícito para evaluar. El uso de técnicas de seguridad sin autorización es ilegal.

## 📄 Licencia

Este proyecto es de código abierto y está disponible bajo la licencia MIT.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue primero para discutir los cambios que te gustaría realizar.

## 📞 Soporte

Si tienes problemas con el despliegue:
- Revisa la [documentación de Vercel](https://vercel.com/docs)
- Verifica que todas las dependencias estén instaladas correctamente
- Asegúrate de que el build se complete sin errores localmente

---

**Hecho con ❤️ para la comunidad de desarrolladores**
