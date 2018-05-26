package main

import (
	"fmt"
	"net"
	"strconv"
)

const (
	socks_port    = ":1080"
	reqAuthMethod = auth_logpass
	debug         = true

	socks_ver      = 0x05 //SOCKS5
	auth_noauth    = 0x00 //no authentication
	auth_GSSAPI    = 0x01 //GSSAPI
	auth_logpass   = 0x02 //username/password
	auth_error     = 0xFF //no acceptable methods were offered
	lpauth_ver     = 0x01 //username/password authentication version
	lpauth_succ    = 0x00 //username/password authentication success
	lpauth_unsucc  = 0x01 //username/password authentication unsuccess
	cmd_TCPconn    = 0x01 //establish a TCP/IP stream connection
	cmd_TCPport    = 0x02 //establish a TCP/IP port binding
	cmd_UDPport    = 0x03 //associate a UDP port
	addrtype_IPv4  = 0x01 //IPv4 address
	addrtype_DN    = 0x03 //domain name
	addrtype_IPv6  = 0x04 //IPv6 address
	status_ok      = 0x00 //request granted
	status_err     = 0x01 //general failure
	status_RSerr   = 0x02 //connection not allowed by ruleset
	status_neterr  = 0x03 //network unreachable
	status_hosterr = 0x04 //host unreachable
	status_connerr = 0x05 //connection refused by destination host
	status_TTLerr  = 0x06 //TTL expired
	status_cmderr  = 0x07 //command not supported / protocol error
	status_addrerr = 0x08 //address type not supported
)

func main() {
	listener, err := net.Listen("tcp", socks_port)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()
	fmt.Println("Server started on ", socks_port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			conn.Close()
			continue
		}
		fmt.Println("New connection accepted: ", conn.RemoteAddr())
		go greetingHandler(conn)
	}
}

func greetingHandler(conn net.Conn) {
	buff := make([]byte, 64)
	n, err := conn.Read(buff)
	if n == 0 || err != nil { //connection error
		fmt.Println("greetingHandler connection closed: ", err, conn.RemoteAddr())
		conn.Close()
		return
	}
	if n > 2 { //we need at least 3 bytes of data
		if buff[0] == socks_ver {
			if n > int(buff[1]+1) { //we need at least 2+numOfAuthMethods bytes of data
				authMethods := buff[2 : buff[1]+2]
				for _, method := range authMethods {
					if method == reqAuthMethod {
						fmt.Println("greetingHandler: chosen method ", reqAuthMethod, conn.RemoteAddr())
						data := []byte{socks_ver, reqAuthMethod}
						conn.Write(data)
						switch reqAuthMethod {
						case auth_noauth:
							cmdHandler(conn)
						case auth_logpass:
							authHandler(conn)
						}
						return
					}
				}
				fmt.Println("greetingHandler error: unsupported auth method", conn.RemoteAddr())
				data := []byte{socks_ver, auth_error}
				conn.Write(data)
				conn.Close()
				return
			}
		} else {
			fmt.Println("greetingHandler error: unsupported socks version ", buff[0], conn.RemoteAddr())
			conn.Close()
			return
		}
	}
	fmt.Println("greetingHandler error: input pocket is broken", conn.RemoteAddr())
	conn.Close()
	return
}

func authHandler(conn net.Conn) {
	buff := make([]byte, 512)
	n, err := conn.Read(buff)
	if n == 0 || err != nil { //connection error
		fmt.Println("authHandler connection closed: ", err, conn.RemoteAddr())
		conn.Close()
		return
	}
	if buff[0] == lpauth_ver {
		logLen := buff[1]
		if n > int(logLen+3) { //we need at least 2+logLen+1 bytes of data
			login := string(buff[2 : logLen+2])
			passLen := buff[logLen+2]
			if n > int(logLen+passLen+2) { //we need at least 2+logLen+passLen bytes of data
				pass := string(buff[logLen+3 : logLen+passLen+3])
				if auth(login, pass) {
					fmt.Println("authHandler: correct log/pass ", login, pass, conn.RemoteAddr())
					data := []byte{lpauth_ver, lpauth_succ}
					conn.Write(data)
					cmdHandler(conn)
					return
				} else {
					fmt.Println("authHandler error: incorrect log/pass ", login, pass, conn.RemoteAddr())
					data := []byte{lpauth_ver, lpauth_unsucc}
					conn.Write(data)
					fmt.Println("authHandler connection closed:", conn.RemoteAddr())
					conn.Close()
					return
				}
			}
		}
		fmt.Println("authHandler error: input pocket is broken", conn.RemoteAddr())
		conn.Close()
		return
	} else {
		fmt.Println("authHandler error: unsupported lpauth version ", buff[0], conn.RemoteAddr())
		conn.Close()
	}
}

func auth(login, pass string) bool {
	//TODO: 3 slices instead map: user, pass, account type
	var userList map[string]string = map[string]string{
		"user1": "abc",
		"user2": "def",
		"user3": "ghi",
		"user4": "jkl",
	}
	for clogin, cpass := range userList {
		if login == clogin && pass == cpass {
			return true
		}
	}
	return false
}

func cmdHandler(userConn net.Conn) {
	buff := make([]byte, 512)
	n, err := userConn.Read(buff)
	if n == 0 || err != nil {
		fmt.Println("cmdHandler connection closed: ", err, userConn.RemoteAddr())
		userConn.Close()
		return
	}
	if n > 3 { //we need at least 4 bytes of data
		if buff[0] == socks_ver {
			switch buff[1] { // TODO support other commands
			case cmd_TCPconn:
				switch buff[3] { // TODO support IPv6 and DN
				case addrtype_IPv4:
					if n > 9 { //we need at least 10 bytes of data
						addr := strconv.Itoa(int(buff[4])) + "." + strconv.Itoa(int(buff[5])) + "." + strconv.Itoa(int(buff[6])) + "." + strconv.Itoa(int(buff[7]))
						port := ":" + strconv.Itoa((int(buff[8])<<8)|int(buff[9]))
						serverConn, status := establishConnection(addr, port)
						data := append([]byte{socks_ver, status, 0, addrtype_IPv4}, buff[4:n]...)
						userConn.Write(data)
						if status == status_ok {
							go connectionHandler(serverConn, userConn)
							go connectionHandler(userConn, serverConn)
							return
						} else {
							userConn.Close()
							if serverConn != nil { //if host is unavailable, connection can doesn't exist
								serverConn.Close()
							}
							return
						}
					} else {
						fmt.Println("cmdHandler error: input pocket is broken", userConn.RemoteAddr())
						userConn.Close()
						return
					}
				case addrtype_DN:
					fmt.Println("cmdHandler error: unsupported addres type ", buff[3], userConn.RemoteAddr())
					data := []byte{socks_ver, status_addrerr, 0}
					userConn.Write(data)
					userConn.Close()
					return
				default:
					fmt.Println("cmdHandler error: unsupported addres type ", buff[3], userConn.RemoteAddr())
					data := []byte{socks_ver, status_addrerr, 0}
					userConn.Write(data)
					userConn.Close()
					return
				}
			default:
				fmt.Println("cmdHandler error: unsupported command ", buff[1], userConn.RemoteAddr())
				data := []byte{socks_ver, status_cmderr, 0}
				userConn.Write(data)
				userConn.Close()
				return
			}
		} else {
			fmt.Println("cmdHandler error: unsupported socks version ", buff[0], userConn.RemoteAddr())
			userConn.Close()
			return
		}
	}
	fmt.Println("cmdHandler error: input pocket is broken", userConn.RemoteAddr())
	userConn.Close()
}

func establishConnection(addr, port string) (net.Conn, byte) {
	conn, err := net.Dial("tcp", addr+port)
	if err != nil {
		fmt.Println(err)
		return conn, status_hosterr
	} else {
		return conn, status_ok
	}
}

func connectionHandler(conn1, conn2 net.Conn) {
	input := make([]byte, 1024*128)
	for {
		n, err := conn1.Read(input)
		if n == 0 || err != nil {
			conn1.Close()
			conn2.Close()
			return
		}
		conn2.Write(input[:n])
	}
}
