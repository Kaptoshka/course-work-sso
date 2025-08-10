package auth

import (
	"context"

	ssov1 "github.com/Kaptoshka/course-work-protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	emptyValue = 0
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (res *ssov1.LoginResponse, err error) {
	if err := validateLogin(req); err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		// TODO: ...
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (res *ssov1.RegisterResponse, err error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userID, err := s.auth.RegisterNewUser(req.GetEmail(), req.GetPassword())
	if err != nil {
		// TODO: implement more error handling
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument(), "email is required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument(), "password is required")
	}

	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument(), "app_id is required")
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument(), "email is required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument(), "password is required")
	}

	return nil
}
