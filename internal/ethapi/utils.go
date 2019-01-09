package ethapi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/ecies"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/node"
)

func EncryptUserData(userData []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	encrypted, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(pubKey), userData, nil, nil)
	return encrypted, err
}
func DecryptUserData(userData []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	decrypted, err := ecies.ImportECDSA(privateKey).Decrypt(rand.Reader, userData, nil, nil)
	return decrypted, err
}
func GetUserIdFromData(jsonData []byte) string {
	var data map[string]string
	if err := json.Unmarshal(jsonData, &data); err != nil {
		log.Error("Unpack data error!")
	}
	idType := data["certype"]
	idNum := data["id"]
	userId := crypto.Keccak256Hash([]byte(idType + "-" + idNum)).Hex()
	return userId
}
func GetUserData() []byte {
	userDataPath := filepath.Join(node.DefaultDataDir(), "userData.json")
	dataBytes, _ := readData(userDataPath)
	return dataBytes
}

// GetCert will read user.crt and return certificate string
func GetCert() string {
	certPath := filepath.Join(node.DefaultDataDir(), "user.crt")
	// parse user certificate
	certBytes, _ := readData(certPath)
	certAscii := hex.EncodeToString(certBytes[:])
	return certAscii
}
func readData(filename string) ([]byte, error) {
	userData, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error("Can not read user data", err)
	}
	return userData, err
}

//get public key from contract use index string.
func getPubKeyFromContract(index string) ([]byte, error) {
	//getPubKeyUseID(useID)
	var tmpKey string
	pubKeyBytes, err := hexutil.Decode(tmpKey)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}
func GetIssuerData(ud UserData, useId common.Address, pubKey string) []byte {
	cert := GetCert()
	i := Issuer{Cert: cert, Alg: "RSA", UseId: useId.Str(), PubKey: pubKey, Cdate: "2018-12-26"}
	data, _ := json.Marshal(i)
	return data
}

func GetIdentityData(ud UserData, pubKey *ecdsa.PublicKey) []byte {
	identity := Identity{}
	data, _ := json.Marshal(ud)
	encData, _ := EncryptUserData(data, pubKey)
	identity.Data = string(encData)
	identity.Alg = "ECIES"
	identity.Fpr = crypto.Keccak256Hash([]byte(data)).Hex()

	d, _ := json.Marshal(&identity)

	return d
}
