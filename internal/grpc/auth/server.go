package auth

import (
	"context"

	ssov1 "github.com/Kaptoshka/course-work-protos/gen/go/sso"
	"google.golang.org/grpc"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
}

func Register(gRPC *grpc.Server) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (res *ssov1.LoginResponse, err error) {
	return nil, nil
}
