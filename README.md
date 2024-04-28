ией API. Гайд по использованию API: 1. Регистрация пользователя: - Отправьте POST-запрос на эндпоинт `/api/v1/register` с телом запроса в формате JSON, содержащим поля `login` и `password`. - Пример запроса: ``` curl -X POST -H "Content-Type: application/json" -d '{"login":"testuser","password":"testpassword"}' http://localhost:8080/api/v1/register ``` - В случае успешной регистрации сервер вернет код состояния 200 OK. 2. Вход пользователя: - Отправьте POST-запрос на эндпоинт `/api/v1/login` с телом запроса в формате JSON, содержащим поля `login` и `password`. - Пример запроса: ``` curl -X POST -H "Content-Type: application/json" -d '{"login":"testuser","password":"testpassword"}' http://localhost:8080/api/v1/login ``` - В случае успешного входа сервер вернет JWT токен в теле ответа. 3. Добавление арифметического выражения: - Отправьте POST-запрос на эндпоинт `/expression` с заголовком `Authorization`, содержащим JWT токен, и параметром `expression` в теле запроса. - Пример запроса: ``` curl -X POST -H "Authorization: <token>" -d "expression=1p2p3" http://localhost:8080/expression ``` - Замените `<token>` на фактический JWT токен, полученный после успешного входа пользователя. - В случае успешного добавления выражения сервер вернет код состояния 200 OK. 4. Получение всех выражений пользователя: - Отправьте GET-запрос на эндпоинт `/expressions` с заголовком `Authorization`, содержащим JWT токен. - Пример запроса: ``` curl -X GET -H "Authorization: <token>" http://localhost:8080/expressions ``` - Замените `<token>` на фактический JWT токен, полученный после успешного входа пользователя. - Сервер вернет список всех выражений пользователя в формате JSON. 5. Добавление агентов вычислений: - Отправьте POST-запрос на эндпоинт `/computation_agent` с параметром `add`, указывающим количество агентов для добавления. - Пример запроса: ``` curl -X POST -d "add=2" http://localhost:8080/computation_agent ``` - В случае успешного добавления агентов сервер вернет код состояния 200 OK. 6. Получение статуса агентов вычислений: - Отправьте GET-запрос на эндпоинт `/agents_status`. - Пример запроса: ``` curl -X GET http://localhost:8080/agents_status ``` - Сервер вернет список всех агентов вычислений и их текущий статус в формате JSON. Обратите внимание, что для запросов, требующих аутентификации (добавление выражения и получение выражений пользователя), необходимо включить JWT токен в заголовок `Authorization`. Токен можно получить после успешного входа пользователя. Также убедитесь, что заменили `<token>` на фактический JWT токен, полученный после входа пользователя, перед выполнением запросов, требующих аутентификации.
