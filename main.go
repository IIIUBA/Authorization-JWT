package main

import (
  "database/sql"
  "encoding/json"
  "fmt"
  "log"
  "math/rand"
  "net/http"
  "strconv"
  "strings"
  "sync"
  "time"

  "github.com/Knetic/govaluate"
  "github.com/dgrijalva/jwt-go"
  _ "github.com/mattn/go-sqlite3"
)

type ArithmeticExpression struct {
  ID               string    `json:"id"`
  UserID           string    `json:"user_id"`
  ExpressionString string    `json:"expression"`
  State            string    `json:"state"`
  CreationTime     time.Time `json:"creation_time"`
  LastUpdateTime   time.Time `json:"last_update_time"`
  EvaluationResult float64   `json:"evaluation_result"`
  IsEvaluated      bool      `json:"is_evaluated"`
}

type ComputationAgent struct {
  State      string `json:"state"`
  Identifier int    `json:"identifier"`
}

type ExpressionStore struct {
  sync.Mutex
  db *sql.DB
}

func NewExpressionStore(db *sql.DB) *ExpressionStore {
  return &ExpressionStore{db: db}
}

func (s *ExpressionStore) Add(expression *ArithmeticExpression) error {
  s.Lock()
  defer s.Unlock()
  _, err := s.db.Exec(`INSERT INTO expressions (id, user_id, expression, state, creation_time, last_update_time, evaluation_result, is_evaluated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    expression.ID, expression.UserID, expression.ExpressionString, expression.State, expression.CreationTime, expression.LastUpdateTime, expression.EvaluationResult, expression.IsEvaluated)
  return err
}

func (s *ExpressionStore) GetByUserID(userID string) ([]*ArithmeticExpression, error) {
  s.Lock()
  defer s.Unlock()
  rows, err := s.db.Query(`SELECT id, user_id, expression, state, creation_time, last_update_time, evaluation_result, is_evaluated
        FROM expressions WHERE user_id = ?`, userID)
  if err != nil {
    return nil, err
  }
  defer rows.Close()
  var expressions []*ArithmeticExpression
  for rows.Next() {
    var expr ArithmeticExpression
    err := rows.Scan(&expr.ID, &expr.UserID, &expr.ExpressionString, &expr.State, &expr.CreationTime, &expr.LastUpdateTime, &expr.EvaluationResult, &expr.IsEvaluated)
    if err != nil {
      return nil, err
    }
    expressions = append(expressions, &expr)
  }
  return expressions, nil
}

func (s *ExpressionStore) UpdateState(id string, state string) error {
  s.Lock()
  defer s.Unlock()
  _, err := s.db.Exec(`UPDATE expressions SET state = ?, last_update_time = ? WHERE id = ?`, state, time.Now(), id)
  return err
}

func (s *ExpressionStore) FetchUnprocessedByUserID(userID string) (*ArithmeticExpression, error) {
  s.Lock()
  defer s.Unlock()
  row := s.db.QueryRow(`SELECT id, user_id, expression, state, creation_time, last_update_time, evaluation_result, is_evaluated
        FROM expressions WHERE user_id = ? AND state = 'processing' LIMIT 1`, userID)
  var expr ArithmeticExpression
  err := row.Scan(&expr.ID, &expr.UserID, &expr.ExpressionString, &expr.State, &expr.CreationTime, &expr.LastUpdateTime, &expr.EvaluationResult, &expr.IsEvaluated)
  if err != nil {
    if err == sql.ErrNoRows {
      return nil, nil
    }
    return nil, err
  }
  _, err = s.db.Exec(`UPDATE expressions SET state = 'in progress', last_update_time = ? WHERE id = ?`, time.Now(), expr.ID)
  if err != nil {
    return nil, err
  }
  return &expr, nil
}

type ComputationManager struct {
  agents          []*ComputationAgent
  processingTime  time.Duration
  expressionStore *ExpressionStore
  userStore       *UserStore
}

func NewComputationManager(processingTime time.Duration, expressionStore *ExpressionStore, userStore *UserStore) *ComputationManager {
  return &ComputationManager{
    processingTime:  processingTime,
    expressionStore: expressionStore,
    userStore:       userStore,
  }
}

func (m *ComputationManager) StartAgents(count int) {
  for i := 0; i < count; i++ {
    agent := &ComputationAgent{
      State:      "idle",
      Identifier: len(m.agents) + 1,
    }
    m.agents = append(m.agents, agent)
    go m.runComputationAgent(agent)
  }
}

func (m *ComputationManager) runComputationAgent(agent *ComputationAgent) {
  for {
    users, err := m.userStore.GetAll()
    if err != nil {
      log.Printf("Error fetching users: %v", err)
      continue
    }
    for _, user := range users {
      expr, err := m.expressionStore.FetchUnprocessedByUserID(user.ID)
      if err != nil {
        log.Printf("Error fetching unprocessed expression: %v", err)
        continue
      }
      if expr == nil {
        continue
      }
      agent.State = "working"
      result, err := evaluateExpression(expr.ExpressionString, m.processingTime)
      if err != nil {
        log.Printf("Error evaluating expression: %v", err)
      }
      err = m.expressionStore.UpdateState(expr.ID, "completed")
      if err != nil {
        log.Printf("Error updating expression state: %v", err)
      }
      expr.EvaluationResult = result
      expr.IsEvaluated = err == nil
    }
    agent.State = "idle"
  }
}

func evaluateExpression(exprStr string, processingTime time.Duration) (float64, error) {
  time.Sleep(processingTime)
  expression, err := govaluate.NewEvaluableExpression(exprStr)
  if err != nil {
    return 0, err
  }
  result, err := expression.Evaluate(nil)
  if err != nil {
    return 0, err
  }
  return result.(float64), nil
}

type User struct {
  ID       string `json:"id"`
  Login    string `json:"login"`
  Password string `json:"password"`
}

type UserStore struct {
  sync.Mutex
  db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
  return &UserStore{db: db}
}

func (s *UserStore) Add(user *User) error {
  s.Lock()
  defer s.Unlock()
  _, err := s.db.Exec(`INSERT INTO users (id, login, password) VALUES (?, ?, ?)`, user.ID, user.Login, user.Password)
  return err
}

func (s *UserStore) GetByLogin(login string) (*User, error) {
  s.Lock()
  defer s.Unlock()
  row := s.db.QueryRow(`SELECT id, login, password FROM users WHERE login = ?`, login)
  var user User
  err := row.Scan(&user.ID, &user.Login, &user.Password)
  if err != nil {
    if err == sql.ErrNoRows {
      return nil, nil
    }
    return nil, err
  }
  return &user, nil
}

func (s *UserStore) GetAll() ([]*User, error) {
  s.Lock()
  defer s.Unlock()
  rows, err := s.db.Query(`SELECT id, login, password FROM users`)
  if err != nil {
    return nil, err
  }
  defer rows.Close()
  var users []*User
  for rows.Next() {
    var user User
    err := rows.Scan(&user.ID, &user.Login, &user.Password)
    if err != nil {
      return nil, err
    }
    users = append(users, &user)
  }
  return users, nil
}

func main() {
  db, err := sql.Open("sqlite3", "calculator.db")
  if err != nil {
    log.Fatal(err)
  }
  defer db.Close()

  _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login TEXT UNIQUE,
      password TEXT
    )`)
  if err != nil {
    log.Fatal(err)
  }

  _, err = db.Exec(`CREATE TABLE IF NOT EXISTS expressions (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      expression TEXT,
      state TEXT,
      creation_time TIMESTAMP,
      last_update_time TIMESTAMP,
      evaluation_result REAL,
      is_evaluated INTEGER,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`)
  if err != nil {
    log.Fatal(err)
  }

  expressionStore := NewExpressionStore(db)
  userStore := NewUserStore(db)
  computationManager := NewComputationManager(10*time.Second, expressionStore, userStore)

  http.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
      http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
      return
    }
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
      http.Error(w, "Invalid request body", http.StatusBadRequest)
      return
    }
    user.ID = createUniqueID()
    err = userStore.Add(&user)
    if err != nil {
      http.Error(w, "Failed to register user", http.StatusInternalServerError)
      return
    }
    w.WriteHeader(http.StatusOK)
  })

  // cURL запрос для регистрации пользователя:
  // curl -X POST -H "Content-Type: application/json" -d '{"login":"testuser","password":"testpassword"}' http://localhost:8080/api/v1/register

  http.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
      http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
      return
    }
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
      http.Error(w, "Invalid request body", http.StatusBadRequest)
      return
    }
    storedUser, err := userStore.GetByLogin(user.Login)
    if err != nil {
      http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
      return
    }
    if storedUser == nil || storedUser.Password != user.Password {
      http.Error(w, "Invalid credentials", http.StatusUnauthorized)
      return
    }
    token := generateJWT(storedUser.ID)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": token})
  })

  // cURL запрос для входа пользователя:
  // curl -X POST-H "Content-Type: application/json" -d '{"login":"testuser","password":"testpassword"}' http://localhost:8080/api/v1/login

  http.HandleFunc("/expression", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
      http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
      return
    }
    expression := r.FormValue("expression")
    expression = strings.ReplaceAll(expression, "p", "+")
    expressionID := r.FormValue("id")
    if expressionID == "" {
      expressionID = createUniqueID()
    }
    userID := r.Header.Get("UserID")
    newExpression := &ArithmeticExpression{
      ID:               expressionID,
      UserID:           userID,
      ExpressionString: expression,
      State:            "processing",
      CreationTime:     time.Now(),
      LastUpdateTime:   time.Now(),
      IsEvaluated:      false,
    }
    err := expressionStore.Add(newExpression)
    if err != nil {
      http.Error(w, "Failed to add expression", http.StatusInternalServerError)
      return
    }
    w.WriteHeader(http.StatusOK)
  }))

  // cURL запрос для добавления арифметического выражения:
  // curl -X POST -H "Authorization: <token>" -d "expression=1p2p3" http://localhost:8080/expression

  http.HandleFunc("/expressions", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
      http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
      return
    }
    userID := r.Header.Get("UserID")
    allExpressions, err := expressionStore.GetByUserID(userID)
    if err != nil {
      http.Error(w, "Failed to retrieve expressions", http.StatusInternalServerError)
      return
    }
    json.NewEncoder(w).Encode(allExpressions)
  }))

  // cURL запрос для получения всех выражений пользователя:
  // curl -X GET -H "Authorization: <token>" http://localhost:8080/expressions

  http.HandleFunc("/computation_agent", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
      http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
      return
    }
    numberToAdd, err := strconv.Atoi(r.FormValue("add"))
    if err != nil {
      http.Error(w, "Value must be an integer", http.StatusBadRequest)
      return
    }
    computationManager.StartAgents(numberToAdd)
    w.WriteHeader(http.StatusOK)
  })

  // cURL запрос для добавления агентов вычислений:
  // curl -X POST -d "add=2" http://localhost:8080/computation_agent

  http.HandleFunc("/agents_status", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
      http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
      return
    }
    json.NewEncoder(w).Encode(computationManager.agents)
  })

  // cURL запрос для получения статуса агентов вычислений:
  // curl -X GET http://localhost:8080/agents_status

  log.Fatal(http.ListenAndServe(":8080", nil))
}

func createUniqueID() string {
  rand.Seed(time.Now().UnixNano())
  return strconv.Itoa(rand.Intn(10000))
}

func generateJWT(userID string) string {
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
    "user_id": userID,
    "exp":     time.Now().Add(time.Hour * 24).Unix(),
  })
  tokenString, _ := token.SignedString([]byte("secret_key"))
  return tokenString
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    tokenString := r.Header.Get("Authorization")
    if tokenString == "" {
      http.Error(w, "Missing token", http.StatusUnauthorized)
      return
    }
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
      if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
      }
      return []byte("secret_key"), nil
    })
    if err != nil {
      http.Error(w, "Invalid token", http.StatusUnauthorized)
      return
    }
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
      userID := claims["user_id"].(string)
      r.Header.Set("UserID", userID)
      next(w, r)
    } else {
      http.Error(w, "Invalid token", http.StatusUnauthorized)
    }
  }
}
