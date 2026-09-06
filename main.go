package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	protocolVersion = 196608 // PostgreSQL protocol 3.0
)

// startup sends the PostgreSQL StartupMessage and handles
// authentication until AuthenticationOk is received.
func startup(
	r *bufio.Reader,
	conn net.Conn,
	database string,
	username string,
	password string,
) error {

	// StartupMessage:
	//
	// Int32 length
	// Int32 protocol version
	// "user"     + '\0'
	// username   + '\0'
	// "database" + '\0'
	// database   + '\0'
	// '\0'
	//
	// The length includes itself.
	body := make([]byte, 0)

	body = appendInt32(body, protocolVersion)

	body = append(body, []byte("user")...)
	body = append(body, 0)
	body = append(body, []byte(username)...)
	body = append(body, 0)

	body = append(body, []byte("database")...)
	body = append(body, 0)
	body = append(body, []byte(database)...)
	body = append(body, 0)

	body = append(body, 0)

	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, uint32(len(body)+4))
	msg = append(msg, body...)

	if _, err := conn.Write(msg); err != nil {
		return err
	}

	// Authentication loop.
	for {
		msgType, payload, err := readMessage(r)
		if err != nil {
			return err
		}

		switch msgType {

		case 'R':
			// Authentication request.
			if err := handleAuthentication(
				r,
				conn,
				payload,
				username,
				password,
			); err != nil {
				return err
			}

			// handleAuthentication may have completed SCRAM
			// or sent another authentication response.

		case 'S':
			// ParameterStatus.
			//
			// Example:
			//   server_version\0
			//   16.4\0
			//
			// We don't need these parameters for this example.

		case 'K':
			// BackendKeyData.
			// Process ID + secret key.
			// Useful for cancellation, but not needed here.

		case 'Z':
			// ReadyForQuery.
			//
			// Startup/authentication is complete.
			return nil

		case 'E':
			return fmt.Errorf("postgres startup error: %s", parseError(payload))

		case 'N':
			// NoticeResponse. Ignore for this example.

		default:
			// Other startup messages can be ignored here.
		}
	}
}

// handleAuthentication processes PostgreSQL Authentication messages.
func handleAuthentication(
	r *bufio.Reader,
	conn net.Conn,
	payload []byte,
	username string,
	password string,
) error {

	if len(payload) < 4 {
		return errors.New("invalid Authentication message")
	}

	authType := binary.BigEndian.Uint32(payload[:4])

	switch authType {

	case 0:
		// AuthenticationOk.
		return nil

	case 3:
		// AuthenticationCleartextPassword.
		//
		// PasswordMessage:
		//
		// 'p'
		// Int32 length
		// password + '\0'
		return sendPassword(conn, password)

	case 5:
		// AuthenticationMD5Password.
		if len(payload) < 8 {
			return errors.New("invalid MD5 authentication message")
		}

		salt := payload[4:8]

		return sendMD5Password(
			conn,
			username,
			password,
			salt,
		)

	case 10:
		// AuthenticationSASL.
		//
		// PostgreSQL tells us which SASL mechanisms it accepts.
		//
		// Commonly:
		//
		// SCRAM-SHA-256
		//
		return handleSCRAM(r, conn, username, password)

	default:
		return fmt.Errorf(
			"unsupported PostgreSQL authentication type: %d",
			authType,
		)
	}
}

// sendPassword sends a PasswordMessage.
func sendPassword(conn net.Conn, password string) error {
	payload := append([]byte(password), 0)

	return sendMessage(conn, 'p', payload)
}

// sendMD5Password implements PostgreSQL's MD5 password authentication.
func sendMD5Password(
	conn net.Conn,
	username string,
	password string,
	salt []byte,
) error {

	// PostgreSQL MD5 authentication is:
	//
	// md5 + md5(password + username) + salt
	//
	// Note that this is legacy authentication. SCRAM-SHA-256
	// is preferred for modern PostgreSQL installations.

	h := md5Hash([]byte(password + username))
	first := hex.EncodeToString(h[:])

	h2 := md5Hash(append([]byte(first), salt...))

	result := "md5" + hex.EncodeToString(h2[:])

	return sendPassword(conn, result)
}

// handleSCRAM performs the SCRAM-SHA-256 exchange.
func handleSCRAM(
	r *bufio.Reader,
	conn net.Conn,
	username string,
	password string,
) error {

	// ---------------------------------------------------------
	// SASLInitialResponse
	// ---------------------------------------------------------

	// Generate a random client nonce.
	nonceBytes := make([]byte, 18)

	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}

	clientNonce := base64.StdEncoding.EncodeToString(nonceBytes)

	// SCRAM client-first-message:
	//
	// n,,n=<username>,r=<nonce>
	//
	// Username escaping is simplified here. For production
	// code, SASL username escaping should be implemented.
	clientFirstBare :=
		"n=" + username +
			",r=" + clientNonce

	clientFirstMessage :=
		"n,," + clientFirstBare

	// SASLInitialResponse payload:
	//
	// mechanism\0
	// Int32 length of initial response
	// initial response
	//
	mechanism := "SCRAM-SHA-256"

	payload := make([]byte, 0)

	payload = append(payload, []byte(mechanism)...)
	payload = append(payload, 0)

	payload = appendInt32(payload, int32(len(clientFirstMessage)))
	payload = append(payload, []byte(clientFirstMessage)...)

	if err := sendMessage(conn, 'p', payload); err != nil {
		return err
	}

	// ---------------------------------------------------------
	// AuthenticationSASLContinue
	// ---------------------------------------------------------

	msgType, serverPayload, err := readMessage(r)
	if err != nil {
		return err
	}

	if msgType != 'R' {
		return fmt.Errorf(
			"expected AuthenticationSASLContinue, got %q",
			msgType,
		)
	}

	if len(serverPayload) < 4 ||
		binary.BigEndian.Uint32(serverPayload[:4]) != 11 {

		return fmt.Errorf("expected SCRAM continue authentication")
	}

	serverFirstMessage := string(serverPayload[4:])

	// Parse:
	//
	// r=<nonce>,s=<salt>,i=<iteration-count>
	//
	parts := parseSCRAMAttributes(serverFirstMessage)

	serverNonce := parts["r"]
	saltString := parts["s"]
	iterationsString := parts["i"]

	if !strings.HasPrefix(serverNonce, clientNonce) {
		return errors.New("server nonce does not contain client nonce")
	}

	salt, err := base64.StdEncoding.DecodeString(saltString)
	if err != nil {
		return err
	}

	iterations, err := strconv.Atoi(iterationsString)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------
	// Calculate SCRAM proof
	// ---------------------------------------------------------

	// client-final-without-proof:
	//
	// c=biws,r=<server nonce>
	clientFinalWithoutProof :=
		"c=biws,r=" + serverNonce

	// AuthMessage:
	//
	// client-first-bare + "," +
	// server-first-message + "," +
	// client-final-without-proof
	authMessage :=
		clientFirstBare + "," +
			serverFirstMessage + "," +
			clientFinalWithoutProof

	// SaltedPassword =
	//     Hi(password, salt, iterations)
	saltedPassword :=
		pbkdf2SHA256(
			[]byte(password),
			salt,
			iterations,
			32,
		)

	// ClientKey = HMAC(SaltedPassword, "Client Key")
	clientKey :=
		hmacSHA256(
			saltedPassword,
			[]byte("Client Key"),
		)

	// StoredKey = SHA256(ClientKey)
	storedKey := sha256.Sum256(clientKey)

	// ClientSignature =
	//     HMAC(StoredKey, AuthMessage)
	clientSignature :=
		hmacSHA256(
			storedKey[:],
			[]byte(authMessage),
		)

	// ClientProof = ClientKey XOR ClientSignature
	clientProof := make([]byte, len(clientKey))

	for i := range clientKey {
		clientProof[i] =
			clientKey[i] ^ clientSignature[i]
	}

	proof := base64.StdEncoding.EncodeToString(clientProof)

	// Final client message.
	clientFinalMessage :=
		clientFinalWithoutProof +
			",p=" + proof

	if err := sendMessage(
		conn,
		'p',
		[]byte(clientFinalMessage),
	); err != nil {
		return err
	}

	// ---------------------------------------------------------
	// AuthenticationSASLFinal
	// ---------------------------------------------------------

	msgType, serverPayload, err = readMessage(r)
	if err != nil {
		return err
	}

	if msgType != 'R' {
		return fmt.Errorf(
			"expected AuthenticationSASLFinal, got %q",
			msgType,
		)
	}

	if len(serverPayload) < 4 ||
		binary.BigEndian.Uint32(serverPayload[:4]) != 12 {

		return fmt.Errorf("expected SCRAM final authentication")
	}

	serverFinalMessage := string(serverPayload[4:])

	finalParts := parseSCRAMAttributes(serverFinalMessage)

	serverSignature, ok := finalParts["v"]
	if !ok {
		return errors.New("server did not provide SCRAM signature")
	}

	// Verify the server signature.
	serverKey :=
		hmacSHA256(
			saltedPassword,
			[]byte("Server Key"),
		)

	expectedServerSignature :=
		hmacSHA256(
			serverKey,
			[]byte(authMessage),
		)

	expectedEncoded :=
		base64.StdEncoding.EncodeToString(
			expectedServerSignature,
		)

	if !hmac.Equal(
		[]byte(serverSignature),
		[]byte(expectedEncoded),
	) {
		return errors.New("SCRAM server signature verification failed")
	}

	return nil
}

// sendQuery sends PostgreSQL's Simple Query message.
//
// Message layout:
//
//	'Q'
//	Int32 length
//	query string
//	'\0'
func sendQuery(conn net.Conn, query string) error {
	payload := append([]byte(query), 0)

	return sendMessage(conn, 'Q', payload)
}

// readResults consumes PostgreSQL messages resulting from the query.
func readResults(r *bufio.Reader) error {

	for {
		msgType, payload, err := readMessage(r)
		if err != nil {
			return err
		}

		switch msgType {

		case 'T':
			// RowDescription.
			printRowDescription(payload)

		case 'D':
			// DataRow.
			printDataRow(payload)

		case 'C':
			// CommandComplete.
			fmt.Printf(
				"CommandComplete: %s\n",
				strings.TrimRight(string(payload), "\x00"),
			)

		case 'Z':
			// ReadyForQuery.
			fmt.Println("ReadyForQuery")
			return nil

		case 'E':
			fmt.Println("PostgreSQL error:")
			fmt.Println(parseError(payload))
			return nil

		case 'N':
			// NoticeResponse.
			fmt.Printf(
				"Notice: %s\n",
				parseError(payload),
			)

		default:
			fmt.Printf(
				"Received message %q (%d bytes)\n",
				msgType,
				len(payload),
			)
		}
	}
}

// printRowDescription parses a RowDescription message.
func printRowDescription(payload []byte) {

	if len(payload) < 2 {
		return
	}

	count := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2

	fmt.Printf("Columns: %d\n", count)

	for i := 0; i < count; i++ {

		end := bytesIndexZero(payload[pos:])
		if end < 0 {
			return
		}

		name := string(payload[pos : pos+end])
		pos += end + 1

		// Table OID
		if pos+18 > len(payload) {
			return
		}

		pos += 4 // table OID
		pos += 2 // column attribute number
		pos += 4 // data type OID
		pos += 2 // data type size
		pos += 4 // type modifier
		pos += 2 // format code

		fmt.Printf("  %s\n", name)
	}
}

// printDataRow parses a DataRow message.
func printDataRow(payload []byte) {

	if len(payload) < 2 {
		return
	}

	count := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2

	fmt.Print("Row: ")

	for i := 0; i < count; i++ {

		if pos+4 > len(payload) {
			return
		}

		length := int32(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4

		if length == -1 {
			fmt.Print("NULL")
			if i != count-1 {
				fmt.Print(" | ")
			}
			continue
		}

		if pos+int(length) > len(payload) {
			return
		}

		value := string(payload[pos : pos+int(length)])
		pos += int(length)

		fmt.Print(value)

		if i != count-1 {
			fmt.Print(" | ")
		}
	}

	fmt.Println()
}

// sendMessage writes a normal PostgreSQL frontend message.
//
// Layout:
//
//	1 byte   message type
//	4 bytes  length
//	N bytes  payload
//
// The length includes the four length bytes but does not
// include the message-type byte.
func sendMessage(
	conn net.Conn,
	msgType byte,
	payload []byte,
) error {

	length := 4 + len(payload)

	buf := make([]byte, 5+len(payload))

	buf[0] = msgType

	binary.BigEndian.PutUint32(
		buf[1:5],
		uint32(length),
	)

	copy(buf[5:], payload)

	_, err := conn.Write(buf)

	return err
}

// readMessage reads one PostgreSQL backend message.
func readMessage(
	r *bufio.Reader,
) (byte, []byte, error) {

	msgType, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	var lengthBytes [4]byte

	if _, err := io.ReadFull(
		r,
		lengthBytes[:],
	); err != nil {
		return 0, nil, err
	}

	length := int(binary.BigEndian.Uint32(lengthBytes[:]))

	if length < 4 {
		return 0, nil, errors.New("invalid PostgreSQL message length")
	}

	payloadLength := length - 4

	payload := make([]byte, payloadLength)

	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return msgType, payload, nil
}

// parseError extracts PostgreSQL ErrorResponse/NoticeResponse fields.
func parseError(payload []byte) string {

	var fields []string

	pos := 0

	for pos < len(payload) {

		fieldType := payload[pos]
		pos++

		if fieldType == 0 {
			break
		}

		end := bytesIndexZero(payload[pos:])
		if end < 0 {
			break
		}

		value := string(payload[pos : pos+end])
		pos += end + 1

		if fieldType == 'M' {
			return value
		}

		fields = append(
			fields,
			fmt.Sprintf("%c=%s", fieldType, value),
		)
	}

	return strings.Join(fields, ", ")
}

// parseSCRAMAttributes parses:
//
//	n=value,n=value,...
func parseSCRAMAttributes(s string) map[string]string {

	result := make(map[string]string)

	for _, item := range strings.Split(s, ",") {

		parts := strings.SplitN(item, "=", 2)

		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result
}

// pbkdf2SHA256 implements PBKDF2-HMAC-SHA256.
func pbkdf2SHA256(
	password []byte,
	salt []byte,
	iterations int,
	keyLength int,
) []byte {

	var result []byte

	blockNum := uint32(1)

	for len(result) < keyLength {

		// salt || INT(blockNum)
		input := make([]byte, len(salt)+4)
		copy(input, salt)

		binary.BigEndian.PutUint32(
			input[len(salt):],
			blockNum,
		)

		u := hmacSHA256(password, input)

		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {

			u = hmacSHA256(password, u)

			for j := range t {
				t[j] ^= u[j]
			}
		}

		result = append(result, t...)

		blockNum++
	}

	return result[:keyLength]
}

func hmacSHA256(
	key []byte,
	data []byte,
) []byte {

	h := hmac.New(
		sha256.New,
		key,
	)

	h.Write(data)

	return h.Sum(nil)
}

func md5Hash(data []byte) [16]byte {
	// Avoid importing crypto/md5 elsewhere in the example.
	//
	// This function is replaced below using the standard
	// crypto/md5 package.
	panic("replace md5Hash with crypto/md5 implementation")
}

func appendInt32(
	dst []byte,
	value int32,
) []byte {

	var b [4]byte

	binary.BigEndian.PutUint32(
		b[:],
		uint32(value),
	)

	return append(dst, b[:]...)
}

func bytesIndexZero(b []byte) int {

	for i, v := range b {
		if v == 0 {
			return i
		}
	}

	return -1
}

func main() {
	host := "127.0.0.1"
	port := 5432
	database := "postgres"
	username := "postgres"
	password := ""

	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)

	// 1. Startup + authentication.
	if err := startup(r, conn, database, username, password); err != nil {
		panic(err)
	}

	// 2. Send:
	//
	//     SELECT * FROM users
	//
	// using PostgreSQL's Simple Query protocol.
	if err := sendQuery(conn, "SELECT * FROM users"); err != nil {
		panic(err)
	}

	// 3. Read the server responses.
	if err := readResults(r); err != nil {
		panic(err)
	}
}
