VERSION=$(shell ./openvpn-collision-manager --version)

deps:
	#git config http.sslVerify false
	#export GIT_SSL_NO_VERIFY=true
	#go get -insecure -v
	go get -v

init:
	go mod init || true

runprod:
	sudo go run .  /etc/openvpn/openvpn-status-tcp.log /etc/openvpn/openvpn-status-udp.log

run:
	killall tail || true
	tail -f /var/log/openvpn-collision-manager.log &
	sudo go run . ~/version1.log ~/version2.log

runold:
	killall tail || true
	tail -f /var/log/openvpn-collision-manager.log &
	sudo go run . ~/version1.log

runnew:
	killall tail || true
	tail -f /var/log/openvpn-collision-manager.log &
	sudo go run . ~/version2.log

test:
	curl -s localhost:8888/users/frank@fandom.com

build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w"
	# upx openvpn-collision-manager

upload:
	curl -H 'X-JFrog-Art-Api: $(APIKEY)' -T ./openvpn-collision-manager  "https://artifactory.wikia-inc.com/artifactory/binaries/chef/autobox/openvpn_colman_$(VERSION)"


all: init deps build
