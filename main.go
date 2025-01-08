package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

var clients = make(map[string]net.Conn)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Неправильная подача аргументов ")
		return
	}

	mode := os.Args[1]
	if mode == "server" {
		port := os.Args[3]
		startServer(port)
	} else if mode == "client" {
		if len(os.Args) < 5 {
			fmt.Println("Неправильное использование клиента ")
			return
		}
		ip := os.Args[2]
		port := os.Args[3]
		nickname := os.Args[4]
		startClient(ip, port, nickname)
	}
}

func startServer(port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Ошибка запуска сервера:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Сервер запущен на порту", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Ошибка подключения клиента:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	nickname, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Ошибка чтения никнейма:", err)
		return
	}

	nickname = strings.TrimSpace(nickname)
	if _, exists := clients[nickname]; exists {
		conn.Write([]byte("Никнейм уже используется\n"))
		return
	}

	clients[nickname] = conn
	fmt.Println(nickname, "подключился")
	broadcast(nickname+" вошел в чат", conn)

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(nickname, "отключился")
			delete(clients, nickname)
			broadcast(nickname+" вышел из чата", conn)
			return
		}

		message = strings.TrimSpace(message)
		if strings.HasPrefix(message, "@") {
			parts := strings.SplitN(message, " ", 2)
			if len(parts) < 2 {
				continue
			}
			recipient := strings.TrimPrefix(parts[0], "@")
			sendPrivateMessage(nickname, recipient, parts[1])
		} else {
			fmt.Println(nickname + ": " + message)
			broadcast(nickname+": "+message, conn)
		}
	}
}

func broadcast(message string, sender net.Conn) {
	for _, client := range clients {
		if client != sender {
			client.Write([]byte(message + "\n"))
		}
	}
}

func sendPrivateMessage(sender, recipient, message string) {
	if conn, exists := clients[recipient]; exists {
		key := generateKey(sender, recipient)
		encryptedMessage, err := encryptMessage(message, key)
		if err != nil {
			clients[sender].Write([]byte("Ошибка шифрования сообщения\n"))
			return
		}
		conn.Write([]byte("от " + sender + ": " + encryptedMessage + "\n"))
	} else {
		if senderConn, exists := clients[sender]; exists {
			senderConn.Write([]byte("Пользователь " + recipient + " не найден\n"))
		}
	}
}

func startClient(ip, port, nickname string) {
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		fmt.Println("Ошибка подключения к серверу:", err)
		return
	}
	defer conn.Close()

	conn.Write([]byte(nickname + "\n"))

	go func() {
		reader := bufio.NewReader(conn)
		for {
			message, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("Отключение от сервера")
				os.Exit(0)
				return
			}

			if strings.HasPrefix(message, "от ") {
				parts := strings.SplitN(message, ": ", 2)
				if len(parts) < 2 {
					fmt.Print(message)
					continue
				}

				sender := strings.TrimPrefix(parts[0], "от ")
				encryptedMessage := parts[1]
				key := generateKey(sender, nickname)

				decryptedMessage, err := decryptMessage(encryptedMessage, key)
				if err != nil {
					fmt.Println("Ошибка дешифровки сообщения:", err)
					continue
				}

				fmt.Println("Приватное сообщение от", sender, ":", decryptedMessage)
			} else {
				fmt.Print(message)
			}
		}
	}()

	fmt.Println("Ваш чат готов!")

	consoleReader := bufio.NewReader(os.Stdin)
	for {
		message, _ := consoleReader.ReadString('\n')
		message = strings.TrimSpace(message)
		if len(message) > 0 {
			conn.Write([]byte(message + "\n"))
		}
	}
}

func generateKey(nickname1, nickname2 string) []byte {
	keyString := nickname1 + nickname2
	hash := sha256.Sum256([]byte(keyString))
	return hash[:]
}

func encryptMessage(message string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(message))
	stream.XORKeyStream(ciphertext, []byte(message))

	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...)), nil
}

func decryptMessage(encryptedMessage string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("недостаточный размер данных")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}
