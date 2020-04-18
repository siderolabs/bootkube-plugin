package asset

func Render(assetDir string, config Config) error {
	as, err := NewDefaultAssets(config)
	if err != nil {
		return err
	}

	err = as.WriteFiles(assetDir)
	if err != nil {
		return err
	}

	return nil
}
