package tests

import (
	"testing"
	"time"

	"sso/tests/suite"

	ssov1 "github.com/Kaptoshka/course-work-protos/gen/go/sso"
	"github.com/brianvoe/gofakeit"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()
	firstName := gofakeit.FirstName()
	lastName := gofakeit.LastName()
	middleName := gofakeit.FirstName()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:      email,
		Password:   pass,
		FirstName:  firstName,
		LastName:   lastName,
		MiddleName: middleName,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 10

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"], deltaSeconds)
}

func TestRegisterLogin_DuplicateRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()
	firstName := gofakeit.FirstName()
	lastName := gofakeit.LastName()
	middleName := gofakeit.FirstName()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:      email,
		Password:   pass,
		FirstName:  firstName,
		LastName:   lastName,
		MiddleName: middleName,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:      email,
		Password:   pass,
		FirstName:  firstName,
		LastName:   lastName,
		MiddleName: middleName,
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		firstName   string
		lastName    string
		middleName  string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			firstName:   gofakeit.FirstName(),
			lastName:    gofakeit.LastName(),
			middleName:  gofakeit.FirstName(),
			expectedErr: "password is required",
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			firstName:   gofakeit.FirstName(),
			lastName:    gofakeit.LastName(),
			middleName:  gofakeit.FirstName(),
			expectedErr: "email is required",
		},
		{
			name:        "Register with Empty First Name",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			firstName:   "",
			lastName:    gofakeit.LastName(),
			middleName:  gofakeit.FirstName(),
			expectedErr: "first_name is required",
		},
		{
			name:        "Register with Empty Last Name",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			firstName:   gofakeit.FirstName(),
			lastName:    "",
			middleName:  gofakeit.FirstName(),
			expectedErr: "last_name is required",
		},
		{
			name:        "Register with Empty Name",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			firstName:   "",
			lastName:    "",
			middleName:  "",
			expectedErr: "first_name is required",
		},
		{
			name:        "Register with Both Empty Email and Password",
			email:       "",
			password:    "",
			firstName:   gofakeit.FirstName(),
			lastName:    gofakeit.LastName(),
			middleName:  gofakeit.FirstName(),
			expectedErr: "email is required",
		},
		{
			name:        "Register with Full Empty",
			email:       "",
			password:    "",
			firstName:   "",
			lastName:    "",
			middleName:  "",
			expectedErr: "email is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:      tt.email,
				Password:   tt.password,
				FirstName:  tt.firstName,
				LastName:   tt.lastName,
				MiddleName: tt.middleName,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Both Empty Email and Password",
			email:       "",
			password:    "",
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Non-Matching Password",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "invalid email or password",
		},
		{
			name:        "Login without AppID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			expectedErr: "app_id is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:      gofakeit.Email(),
				Password:   randomFakePassword(),
				FirstName:  gofakeit.FirstName(),
				LastName:   gofakeit.LastName(),
				MiddleName: gofakeit.FirstName(),
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
