package main

import (
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/docker/notary"
	notaryclient "github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cmdRoleTemplate = usageTemplate{
	Use:   "role",
	Short: "Operates on top-level roles.",
	Long:  `Operations on TUF roles.`,
}

var cmdRoleListTemplate = usageTemplate{
	Use:   "list [ GUN ]",
	Short: "Lists role info for the Global Unique Name.",
	Long:  "Lists top-level role info for a specific Global Unique Name.",
}

var cmdRoleRemoveTemplate = usageTemplate{
	Use:   "remove [ GUN ] [ Role ] <KeyID 1> ...",
	Short: "Remove KeyID(s) from the specified Role.",
	Long:  "Remove KeyID(s) from the specified Role in a specific Global Unique Name.",
}

var cmdRoleAddTemplate = usageTemplate{
	Use:   "add [ GUN ] [ Role ] <X509 file path 1> ...",
	Short: "Add keys to role using the provided public key X509 certificates.",
	Long:  "Add keys to role using the provided public key PEM encoded X509 certificates in a specific Global Unique Name.",
}

var cmdRoleThresholdTemplate = usageTemplate{
	Use:   "threshold [ GUN ] [ Role ] [ Threshold ]",
	Short: "Update Threshold for a Role.",
	Long:  "Update the Threshold (required number of signatures) for a Role in a specific Global Unique Name.",
}

type roleCommander struct {
	// these need to be set
	configGetter func() (*viper.Viper, error)
	retriever    notary.PassRetriever

	paths                         []string
	allPaths, removeAll, forceYes bool
	threshold                     int
}

func (r *roleCommander) GetCommand() *cobra.Command {
	cmd := cmdRoleTemplate.ToCommand(nil)
	cmd.AddCommand(cmdRoleListTemplate.ToCommand(r.rolesList))
	cmd.AddCommand(cmdRoleThresholdTemplate.ToCommand(r.roleThreshold))
	cmdRemRole := cmdRoleRemoveTemplate.ToCommand(r.roleRemove)
	cmdRemRole.Flags().StringSliceVar(&r.paths, "paths", nil, "List of paths to remove")
	cmdRemRole.Flags().BoolVarP(&r.forceYes, "yes", "y", false, "Answer yes to the removal question (no confirmation)")
	cmdRemRole.Flags().BoolVar(&r.allPaths, "all-paths", false, "Remove all paths from this role")
	cmd.AddCommand(cmdRemRole)

	cmdAddRole := cmdRoleAddTemplate.ToCommand(r.roleAdd)
	cmdAddRole.Flags().IntVar(&r.threshold, "threshold", 1, "Threshold of keys required to sign")
	cmdAddRole.Flags().StringSliceVar(&r.paths, "paths", nil, "List of paths to add")
	cmdAddRole.Flags().BoolVar(&r.allPaths, "all-paths", false, "Add all paths to this role")
	cmd.AddCommand(cmdAddRole)
	return cmd
}

// rolesList lists all the roles for a particular GUN
func (r *roleCommander) rolesList(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		cmd.Usage()
		return fmt.Errorf(
			"Please provide a Global Unique Name as an argument to list")
	}

	config, err := r.configGetter()
	if err != nil {
		return err
	}

	gun := args[0]

	rt, err := getTransport(config, gun, readOnly)
	if err != nil {
		return err
	}

	trustPin, err := getTrustPinning(config)
	if err != nil {
		return err
	}

	// initialize repo with transport to get latest state of the world before listing roles
	nRepo, err := notaryclient.NewNotaryRepository(
		config.GetString("trust_dir"), gun, getRemoteTrustServer(config), rt, r.retriever, trustPin)
	if err != nil {
		return err
	}

	roles, err := nRepo.GetAllRoles()
	if err != nil {
		return fmt.Errorf("Error retrieving role roles for repository %s: %v", gun, err)
	}

	cmd.Println("")
	prettyPrintRoles(roles, cmd.Out(), "roles")
	cmd.Println("")
	return nil
}

func (r *roleCommander) roleThreshold(cmd *cobra.Command, args []string) error {
	if len(args) < 3 {
		cmd.Usage()
		return fmt.Errorf("must specify the Global Unique Name and the role along with a threshold number to set")
	}
	gun := args[0]
	role := args[1]
	thresholdArg := args[2]
	threshold, err := strconv.Atoi(thresholdArg)
	if err != nil {
		return fmt.Errorf("Error converting threshold to int: %v", err)
	}

	config, err := r.configGetter()
	if err != nil {
		return err
	}

	trustPin, err := getTrustPinning(config)
	if err != nil {
		return err
	}

	nRepo, err := notaryclient.NewNotaryRepository(
		config.GetString("trust_dir"), gun, getRemoteTrustServer(config), nil, r.retriever, trustPin)
	if err != nil {
		return err
	}

	if err := nRepo.UpdateThreshold(role, threshold); err != nil {
		return err
	}

	cmd.Println("")
	cmd.Printf("Threshold for %v role in %v set to %v and staged for next publish.", role, gun, threshold)
	cmd.Println("")
	return nil
}

// roleRemove removes a public key from a specific role in a GUN
func (r *roleCommander) roleRemove(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		cmd.Usage()
		return fmt.Errorf("must specify the Global Unique Name and the role of the role along with optional keyIDs and/or a list of paths to remove")
	}

	config, err := r.configGetter()
	if err != nil {
		return err
	}

	gun := args[0]
	role := args[1]

	// Check if role is valid role name before requiring any user input
	if !data.ValidRole(role) {
		return fmt.Errorf("invalid role name %s", role)
	}

	// If we're only given the gun and the role, attempt to remove all data for this role
	if len(args) == 2 && r.paths == nil && !r.allPaths {
		r.removeAll = true
	}

	keyIDs := []string{}

	if len(args) > 2 {
		keyIDs = args[2:]
	}

	// If the user passes --all-paths, don't use any of the passed in --paths
	if r.allPaths {
		r.paths = nil
	}

	trustPin, err := getTrustPinning(config)
	if err != nil {
		return err
	}

	// no online operations are performed by add so the transport argument
	// should be nil
	nRepo, err := notaryclient.NewNotaryRepository(
		config.GetString("trust_dir"), gun, getRemoteTrustServer(config), nil, r.retriever, trustPin)
	if err != nil {
		return err
	}

	// Remove the keys from the role
	err = nRepo.RemoveKey(role, keyIDs)
	if err != nil {
		return fmt.Errorf("failed to update role: %v", err)
	}

	// if r.removeAll {
	// 	cmd.Println("\nAre you sure you want to remove all data for this role? (yes/no)")
	// 	// Ask for confirmation before force removing role
	// 	if !r.forceYes {
	// 		confirmed := askConfirm(os.Stdin)
	// 		if !confirmed {
	// 			fatalf("Aborting action.")
	// 		}
	// 	} else {
	// 		cmd.Println("Confirmed `yes` from flag")
	// 	}
	// 	// Delete the entire role
	// 	err = nRepo.RemoveRole(role)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove role: %v", err)
	// 	}
	// } else {
	// 	if r.allPaths {
	// 		err = nRepo.ClearRolePaths(role)
	// 		if err != nil {
	// 			return fmt.Errorf("failed to remove role: %v", err)
	// 		}
	// 	}
	// 	// Remove any keys or paths that we passed in
	// 	err = nRepo.RemoveRoleKeysAndPaths(role, keyIDs, r.paths)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove role: %v", err)
	// 	}
	// }

	cmd.Println("")
	if r.removeAll {
		cmd.Printf("Forced removal (including all keys and paths) of role role %s to repository \"%s\" staged for next publish.\n", role, gun)
	} else {
		removingItems := ""
		if len(keyIDs) > 0 {
			removingItems = removingItems + fmt.Sprintf("keys %s, ", keyIDs)
		}
		if r.allPaths {
			removingItems = removingItems + "with all paths, "
		}
		if r.paths != nil {
			removingItems = removingItems + fmt.Sprintf("with paths [%s], ", prettyPaths(r.paths))
		}
		cmd.Printf(
			"Removal of %sfrom role %s in repository \"%s\" staged for next publish.\n",
			removingItems, role, gun)
	}
	cmd.Println("")

	return nil
}

// roleAdd creates a new role by adding a public key from a certificate to a specific role in a GUN
func (r *roleCommander) roleAdd(cmd *cobra.Command, args []string) error {
	// We must have at least the gun and role name, and at least one key or path (or the --all-paths flag) to add
	if len(args) < 2 || len(args) < 3 && r.paths == nil && !r.allPaths {
		cmd.Usage()
		return fmt.Errorf("must specify the Global Unique Name and the the Role along with the public key certificate paths and/or a list of paths to add")
	}

	config, err := r.configGetter()
	if err != nil {
		return err
	}

	gun := args[0]
	role := args[1]

	pubKeys := []data.PublicKey{}
	if len(args) > 2 {
		pubKeyPaths := args[2:]
		for _, pubKeyPath := range pubKeyPaths {
			// Read public key bytes from PEM file
			pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
			if err != nil {
				return fmt.Errorf("unable to read public key from file: %s", pubKeyPath)
			}

			// Parse PEM bytes into type PublicKey
			pubKey, err := utils.ParsePEMPublicKey(pubKeyBytes)
			if err != nil {
				return fmt.Errorf("unable to parse valid public key certificate from PEM file %s: %v", pubKeyPath, err)
			}
			pubKeys = append(pubKeys, pubKey)
		}
	}

	for _, path := range r.paths {
		if path == "" {
			r.allPaths = true
			break
		}
	}

	// If the user passes --all-paths (or gave the "" path in --paths), give the "" path
	if r.allPaths {
		r.paths = []string{""}
	}

	trustPin, err := getTrustPinning(config)
	if err != nil {
		return err
	}

	// no online operations are performed by add so the transport argument
	// should be nil
	nRepo, err := notaryclient.NewNotaryRepository(
		config.GetString("trust_dir"), gun, getRemoteTrustServer(config), nil, r.retriever, trustPin)
	if err != nil {
		return err
	}

	// Add the key to the role
	err = nRepo.AddKey(role, pubKeys)
	if err != nil {
		return fmt.Errorf("failed to update role: %v", err)
	}

	// Make keyID slice for better CLI print
	pubKeyIDs := []string{}
	for _, pubKey := range pubKeys {
		pubKeyID, err := utils.CanonicalKeyID(pubKey)
		if err != nil {
			return err
		}
		pubKeyIDs = append(pubKeyIDs, pubKeyID)
	}

	cmd.Println("")
	addingItems := ""
	if len(pubKeyIDs) > 0 {
		addingItems = addingItems + fmt.Sprintf("keys %s, ", pubKeyIDs)
	}
	if r.paths != nil || r.allPaths {
		addingItems = addingItems + fmt.Sprintf("with paths [%s], ", prettyPaths(r.paths))
	}
	cmd.Printf(
		"Addition of %sto role %s in repository \"%s\" staged for next publish.\n",
		addingItems, role, gun)
	cmd.Println("")
	return nil
}
