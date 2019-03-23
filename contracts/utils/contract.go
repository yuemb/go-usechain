// Copyright 2018 The go-usechain Authors
// This file is part of the go-usechain library.
//
// The go-usechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usechain library. If not, see <http://www.gnu.org/licenses/>.

package utils

import (
	"github.com/usechain/go-usechain/accounts/abi"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/core/vm"
	"github.com/usechain/go-usechain/params"
	"math/big"
	"sync"
)

const (
	ContractFalse = "0x0000000000000000000000000000000000000000000000000000000000000000"
	ContractTrue  = "0x0000000000000000000000000000000000000000000000000000000000000001"
	ContractZero  = "0x0000000000000000000000000000000000000000000000000000000000000000"
	ContractOne   = "0x0000000000000000000000000000000000000000000000000000000000000001"
)

var (
	big0    = big.NewInt(0)
	big1000 = big.NewInt(1000)

	gasMax core.GasPool = 100000000000000
)

//The struct of contract
type Contracter struct {
	config     *params.ChainConfig
	blockchain *core.BlockChain
	gp         *core.GasPool
	statedb    *state.StateDB
	cfg        vm.Config

	mu sync.Mutex

	author *common.Address
	abi    abi.ABI
}

// NewContract creates a new instance of contract
func NewContracter(bc *core.BlockChain, ctr common.Address, abi abi.ABI) (*Contracter, error) {
	contracter := &Contracter{
		config:     bc.ChainConfig(),
		blockchain: bc,
		gp:         &gasMax,
		cfg:        bc.VmConfig(),

		author: &ctr,
		abi:    abi,
	}

	return contracter, nil
}

// Call the contract and return the message
func (self *Contracter) call(msg *types.Message) ([]byte, error) {
	var err error
	self.statedb, err = self.blockchain.State()
	if err != nil {
		return nil, err
	}

	header := self.blockchain.CurrentHeader()
	// Create a new context to be used in the EVM environment
	context := core.NewEVMContext(msg, header, self.blockchain, self.author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, self.statedb, self.config, self.cfg)
	// Apply the transaction to the current state (included in the env)
	res, _, _, err := core.ApplyMessage(vmenv, msg, self.gp)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Call the contract and return the message
func (self *Contracter) CallContract(from common.Address, nonce uint64, method string, params ...interface{}) ([]byte, error) {
	bytes, err := self.abi.Pack(method, params...)
	if err != nil {
		return nil, err
	}

	msg := types.NewMessage(from, self.author, nonce, big0, uint64(gasMax), big1000, bytes, false)
	return self.call(&msg)
}
