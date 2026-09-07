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

type PGConnection struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (p *PGConnection) Close() {
	if p.conn != nil {
		p.conn.Close()
	}
}

func NewConnection(host string, port int, database, username, password string) (*PGConnection, error) {

	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))

	if err != nil {
		return nil, err
	}
	p := &PGConnection{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}

	err = p.startup(database, username, password)
	if err != nil {
		return nil, err
	}

	return p, nil

}

// startup sends the PostgreSQL StartupMessage and handles
// authentication until AuthenticationOk is received.
func (p *PGConnection) startup(database string, username string, password string) error {

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

	if _, err := p.conn.Write(msg); err != nil {
		return err
	}

	// Authentication loop.
	for {
		msgType, payload, err := p.readMessage()
		if err != nil {
			return err
		}

		switch msgType {

		case 'R':
			// Authentication request.
			if err := p.handleAuthentication(payload, username, password); err != nil {
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
func (p *PGConnection) handleAuthentication(payload []byte, username string, password string) error {

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
		return p.sendPassword(password)

	case 5:
		// AuthenticationMD5Password.
		if len(payload) < 8 {
			return errors.New("invalid MD5 authentication message")
		}

		salt := payload[4:8]
		return p.sendMD5Password(username, password, salt)

	case 10:
		// AuthenticationSASL.
		//
		// PostgreSQL tells us which SASL mechanisms it accepts.
		//
		// Commonly:
		//
		// SCRAM-SHA-256
		//
		return p.handleSCRAM(username, password)

	default:
		return fmt.Errorf("unsupported PostgreSQL authentication type: %d", authType)
	}
}

// sendPassword sends a PasswordMessage.
func (p *PGConnection) sendPassword(password string) error {
	payload := append([]byte(password), 0)
	return p.sendMessage('p', payload)
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
func (p *PGConnection) sendMessage(msgType byte, payload []byte) error {

	length := 4 + len(payload)

	buf := make([]byte, 5+len(payload))

	buf[0] = msgType

	binary.BigEndian.PutUint32(
		buf[1:5],
		uint32(length),
	)

	copy(buf[5:], payload)

	_, err := p.conn.Write(buf)

	return err
}

// readMessage reads one PostgreSQL backend message.
func (p *PGConnection) readMessage() (byte, []byte, error) {

	msgType, err := p.reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	var lengthBytes [4]byte

	if _, err := io.ReadFull(
		p.reader,
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

	if _, err := io.ReadFull(p.reader, payload); err != nil {
		return 0, nil, err
	}

	return msgType, payload, nil
}

func (p *PGConnection) Query(query string) ([][]bool, [][]string, []string, error) {

	err := p.sendQuery(query)
	if err != nil {
		return nil, nil, nil, err
	}

	nulls, data, headers, err := p.readResults()

	columns := make([]string, len(headers))
	for _, h := range headers {
		columns = append(columns, h.name)
	}

	return nulls, data, columns, err

}

// sendQuery sends PostgreSQL's Simple Query message.
//
// Message layout:
//
//	'Q'
//	Int32 length
//	query string
//	'\0'
func (p *PGConnection) sendQuery(query string) error {
	payload := append([]byte(query), 0)
	return p.sendMessage('Q', payload)
}

// sendMD5Password implements PostgreSQL's MD5 password authentication.
func (p *PGConnection) sendMD5Password(username string, password string, salt []byte) error {

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

	return p.sendPassword(result)
}

// handleSCRAM performs the SCRAM-SHA-256 exchange.
func (p *PGConnection) handleSCRAM(username string, password string) error {

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
	clientFirstBare := "n=" + username + ",r=" + clientNonce

	clientFirstMessage := "n,," + clientFirstBare

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

	if err := p.sendMessage('p', payload); err != nil {
		return err
	}

	// ---------------------------------------------------------
	// AuthenticationSASLContinue
	// ---------------------------------------------------------

	msgType, serverPayload, err := p.readMessage()
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
	clientFinalWithoutProof := "c=biws,r=" + serverNonce

	// AuthMessage:
	//
	// client-first-bare + "," +
	// server-first-message + "," +
	// client-final-without-proof
	authMessage := clientFirstBare + "," + serverFirstMessage + "," + clientFinalWithoutProof

	// SaltedPassword =
	//     Hi(password, salt, iterations)
	saltedPassword := pbkdf2SHA256([]byte(password), salt, iterations, 32)

	// ClientKey = HMAC(SaltedPassword, "Client Key")
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))

	// StoredKey = SHA256(ClientKey)
	storedKey := sha256.Sum256(clientKey)

	// ClientSignature =
	//     HMAC(StoredKey, AuthMessage)
	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))

	// ClientProof = ClientKey XOR ClientSignature
	clientProof := make([]byte, len(clientKey))

	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	proof := base64.StdEncoding.EncodeToString(clientProof)

	// Final client message.
	clientFinalMessage :=
		clientFinalWithoutProof +
			",p=" + proof

	if err := p.sendMessage('p', []byte(clientFinalMessage)); err != nil {
		return err
	}

	// ---------------------------------------------------------
	// AuthenticationSASLFinal
	// ---------------------------------------------------------

	msgType, serverPayload, err = p.readMessage()
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
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))

	expectedServerSignature := hmacSHA256(serverKey, []byte(authMessage))

	expectedEncoded := base64.StdEncoding.EncodeToString(expectedServerSignature)

	if !hmac.Equal([]byte(serverSignature), []byte(expectedEncoded)) {
		return errors.New("SCRAM server signature verification failed")
	}

	return nil
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

// readResults consumes PostgreSQL messages resulting from the query.
func (p *PGConnection) readResults() ([][]bool, [][]string, []*tableRowDescription, error) {

	tableHeaderDescriptors := []*tableRowDescription{}
	dataRows := [][]string{}
	nullRows := [][]bool{}
	for {
		msgType, payload, err := p.readMessage()
		if err != nil {
			return nullRows, dataRows, tableHeaderDescriptors, err
		}

		switch msgType {

		case 'T':
			// RowDescription.
			tableHeaderDescriptors = parseRowDescription(payload)

		case 'D':
			// DataRow.
			nr, dr := parseDataRow(payload)
			dataRows = append(dataRows, dr)
			nullRows = append(nullRows, nr)

		case 'C':
			// CommandComplete.

		case 'Z':
			// ReadyForQuery.
			return nullRows, dataRows, tableHeaderDescriptors, nil

		case 'E':
			return nullRows, dataRows, tableHeaderDescriptors, errors.New(parseError(payload))

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

const (
	protocolVersion = 196608 // PostgreSQL protocol 3.0
)

// printRowDescription parses a RowDescription message.

type tableRowDescription struct {
	name                  string
	tableOid              []byte
	columnAttributeNumber []byte
	dataTypeOid           []byte
	dataTypeSize          []byte
	typeModifier          []byte
	formatCode            []byte
}

func parseRowDescription(payload []byte) []*tableRowDescription {

	if len(payload) < 2 {
		return []*tableRowDescription{}
	}

	count := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2

	tableRowDescriptors := []*tableRowDescription{}
	for i := 0; i < count; i++ {

		end := bytesIndexZero(payload[pos:])
		if end < 0 {
			break
		}

		name := string(payload[pos : pos+end])
		pos += end + 1

		// Table OID
		if pos+18 > len(payload) {
			break
		}

		t := &tableRowDescription{
			name: strings.TrimSpace(name),
		}

		t.tableOid = payload[pos : pos+4]
		pos += 4

		t.columnAttributeNumber = payload[pos : pos+2]
		pos += 2

		t.dataTypeOid = payload[pos : pos+4]
		pos += 4

		t.dataTypeSize = payload[pos : pos+2]
		pos += 2

		t.typeModifier = payload[pos : pos+2]
		pos += 4

		t.formatCode = payload[pos : pos+2]
		pos += 2

		tableRowDescriptors = append(tableRowDescriptors, t)
	}

	return tableRowDescriptors
}

// parseDataRow parses a DataRow message.
func parseDataRow(payload []byte) ([]bool, []string) {

	if len(payload) < 2 {
		return []bool{}, []string{}
	}

	count := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2

	rowData := []string{}
	nullData := []bool{}

	for i := 0; i < count; i++ {

		if pos+4 > len(payload) {
			break
		}

		length := int32(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4

		if length == -1 {
			nullData = append(nullData, true)
			rowData = append(rowData, "")
			continue
		}

		nullData = append(nullData, false)

		if pos+int(length) > len(payload) {
			break
		}

		value := string(payload[pos : pos+int(length)])
		rowData = append(rowData, value)
		pos += int(length)

	}

	return nullData, rowData

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
