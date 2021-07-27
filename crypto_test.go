package crypto

import (
	"testing"

	"jupiter.com/config"
)

func TestEncrypt(t *testing.T) {

	var conf config.Config
	conf.Debug = false

	type args struct {
		keyString64     string
		stringToEncrypt string
		conf            config.Config
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ALL OK",
			args: args{
				keyString64:     "fff0f247285d6dc32ea38d9f05d0b5adbe112dba0a6ea73b15f3927f056ead35",
				stringToEncrypt: "admin:Jup1t3r-Aw$01-qw33N@tcp(jupiter-aws.cbmworrme0l2.us-east-2.rds.amazonaws.com:3306)/jupiter",
			},
			want: "5d23032d489cb221845fe6353fb073322599747148025e3afb6ff48df4d6d95446422ae8d7ad78dd4db3fb4223ee42bdbb660f364b9123e8e807fead339e317b6ee99e895169791f924fffbc6ebaebb404f6d92e458ffafd0535bc6ad749888f7f19adb8b84efc00ddb09db72df3e3a6b97eb4df6e78cc6fc2463234"},
		{
			name: "NO KEY",
			args: args{
				keyString64:     "",
				stringToEncrypt: "admin:Jup1t3r-Aw$01-qw33N@tcp(jupiter-aws.cbmworrme0l2.us-east-2.rds.amazonaws.com:3306)/jupiter",
			},
			want: "5d23032d489cb221845fe6353fb073322599747148025e3afb6ff48df4d6d95446422ae8d7ad78dd4db3fb4223ee42bdbb660f364b9123e8e807fead339e317b6ee99e895169791f924fffbc6ebaebb404f6d92e458ffafd0535bc6ad749888f7f19adb8b84efc00ddb09db72df3e3a6b97eb4df6e78cc6fc2463234"},
	}
	for _, tt := range tests {
		got, err := Encrypt(tt.args.keyString64, tt.args.stringToEncrypt)

		if err != nil {
			t.Errorf("%q. Encrypt() error = %v, want %v, got %v", tt.name, err, tt.want, got)
			continue
		}
		/*if got != tt.want {
			t.Errorf("%q. Encrypt() = %v, want %v", tt.name, got, tt.want)
		}*/
	}
}

func TestDecrypt(t *testing.T) {
	type args struct {
		keyString64     string
		encryptedString string
		conf            config.Config
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ALL OK",
			args: args{
				keyString64:     "fff0f247285d6dc32ea38d9f05d0b5adbe112dba0a6ea73b15f3927f056ead35",
				encryptedString: "5d23032d489cb221845fe6353fb073322599747148025e3afb6ff48df4d6d95446422ae8d7ad78dd4db3fb4223ee42bdbb660f364b9123e8e807fead339e317b6ee99e895169791f924fffbc6ebaebb404f6d92e458ffafd0535bc6ad749888f7f19adb8b84efc00ddb09db72df3e3a6b97eb4df6e78cc6fc2463234"},
			want: "admin:Jup1t3r-Aw$01-qw33N@tcp(jupiter-aws.cbmworrme0l2.us-east-2.rds.amazonaws.com:3306)/jupiter",
		},
	}
	for _, tt := range tests {
		got, err := Decrypt(tt.args.keyString64, tt.args.encryptedString)
		if err != nil {
			t.Errorf("%q. Decrypt() error = %v, want %v, got %v", tt.name, err, tt.want, got)
			continue
		}
		if got != tt.want {
			t.Errorf("%q. Decrypt() error = %v, want %v, got %v", tt.name, err, tt.want, got)
		}
	}
}
