package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	validator "github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	Path string
)

// NewValidateCmd creates a new token command.
func NewValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "validate",
		Short:        "Validates all packages with the path supplied",
		Long:         "",
		Example:      "package-validator validate --path carvel-artifacts",
		Aliases:      []string{"v"},
		RunE:         validate,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&Path, "path", "p", "carvel-artifacts", "The path to the carvel packages")

	return cmd
}

func validate(cmd *cobra.Command, args []string) error {
	filepath.WalkDir(Path,
		func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				component := filepath.Base(filepath.Dir(path))
				if d.Name() == "package.yml" {
					packageCRs[component] = path
				}
				if d.Name() == "metadata.yml" {
					packageMetadataCRs[component] = path
				}
			}
			return nil
		})

	err := multierr.Combine(
		ValidatePackageCR(),
		ValidatePackageMetadataCR(),
		ValidateAnnotationSize(),
	)

	errors := multierr.Errors(err)
	if len(errors) > 0 {
		for _, e := range errors {
			logrus.Errorf("%s", e)
		}
	}

	return err
}

var packageCRs = map[string]string{}         // {component: Package CR path}
var packageMetadataCRs = map[string]string{} // {component: PackageMetadata CR path}

func ValidatePackageCR() error {
	for component, packageCR := range packageCRs {
		err := func() error {
			component, packageCR := component, packageCR // shadow loop variable for goroutine: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables

			fields := &struct {
				APIVersion string `yaml:"apiVersion" validate:"required,eq=data.packaging.carvel.dev/v1alpha1"`
				Kind       string `yaml:"kind" validate:"required,eq=Package"`
				Metadata   struct {
					Name string `yaml:"name" validate:"required,metadata-name"`
				} `yaml:"metadata"`
				Spec struct {
					RefName      string    `yaml:"refName" validate:"required"`
					Version      string    `yaml:"version" validate:"required"`
					ReleasedAt   time.Time `yaml:"releasedAt"`
					ValuesSchema struct {
					} `yaml:"valuesSchema" validate:"required"`
					Template struct {
						Spec struct {
							Fetch []struct {
								ImgpkgBundle struct {
									Image string `yaml:"image" validate:"required,imgpkgBundle-image-format,no-manifests"`
								} `yaml:"imgpkgBundle" validate:"required"`
							} `yaml:"fetch" validate:"required,max=1,dive"`
							Template []struct {
								Ytt struct {
									Paths []string `yaml:"paths"`
								} `yaml:"ytt" validate:"required"`
								Kbld struct {
									Paths []string `yaml:"paths" validate:"kbld-paths"`
								} `yaml:"kbld" validate:"required"`
							} `yaml:"template" validate:"required,dive"`
							Deploy []struct {
								Kapp struct {
								} `yaml:"kapp" validate:"required"`
							} `yaml:"deploy" validate:"required,dive"`
						} `yaml:"spec" validate:"required"`
					} `yaml:"template" validate:"required"`
				} `yaml:"spec" validate:"required"`
			}{}

			validate := validator.New()

			// register custom validation for "{metadata.name} == {spec.refName}.{spec.version}"
			err := validate.RegisterValidation("metadata-name", func(fl validator.FieldLevel) bool {
				metadataName := fl.Field().String()
				refName := fl.Top().Elem().FieldByName("Spec").FieldByName("RefName").String()
				version := fl.Top().Elem().FieldByName("Spec").FieldByName("Version").String()

				ok := (metadataName == refName+"."+version)
				if !ok {
					logrus.Errorf(`Validation "{metadata.name} == {spec.refName}.{spec.version}" unsuccessful (%s != %s.%s)`, metadataName, refName, version)
				} else {
					logrus.Infof(`Validation "{metadata.name} == {spec.refName}.{spec.version}" successful (%s)`, metadataName)
				}

				return ok
			})
			if err != nil {
				return fmt.Errorf(`Failed to add custom validation for "{metadata.name} == {spec.refName}.{spec.version}": %s`, err)
			}

			// register custom validation for "{spec.template.spec.fetch[0].imgpkgBundle.image} is dev.registry.tanzu.vmware.com reference"
			err = validate.RegisterValidation("imgpkgBundle-image-format", func(fl validator.FieldLevel) bool {
				imgpkgBundle := fl.Field().String()

				// check if dev registry image
				ok := regexp.MustCompile(`^dev\.registry\.tanzu\.vmware\.com/.+@sha256:[a-f0-9]{64}$`).MatchString(imgpkgBundle)
				if !ok {
					logrus.Errorf(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} is dev.registry.tanzu.vmware.com reference" unsuccessful for %s`, imgpkgBundle)
				} else {
					logrus.Infof(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} is dev.registry.tanzu.vmware.com reference" successful for %s`, imgpkgBundle)
				}

				return ok
			})
			if err != nil {
				return fmt.Errorf(`Failed to add custom validation for "{spec.template.spec.fetch[0].imgpkgBundle.image} is dev.registry.tanzu.vmware.com reference": %s`, err)
			}

			// register custom validation for "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests"
			err = validate.RegisterValidation("no-manifests", func(fl validator.FieldLevel) bool {
				imgpkgBundle := fl.Field().String()

				imgpkgDescribe := &struct {
					Content struct {
						Images map[string]struct {
							Image string `yaml:"image"`
						} `yaml:"images"`
					} `yaml:"content"`
				}{}

				// describe images in the bundle
				cmd := exec.Command("imgpkg", "describe", "-b", imgpkgBundle, "-o", "yaml")
				output, err := cmd.CombinedOutput()
				if err != nil {
					logrus.Errorf("Failed to get imgpkg describe for bundle %s: %s: %s (%s)", imgpkgBundle, err, output, strings.Join(cmd.Args, " "))
					logrus.Errorf(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests" unsuccessful for %s`, imgpkgBundle)
					return false
				}

				err = yaml.Unmarshal(output, imgpkgDescribe)
				if err != nil {
					logrus.Errorf("Failed to unmarshal imgpkg describe output for bundle %s: %s", imgpkgBundle, err)
					logrus.Errorf(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests" unsuccessful for %s`, imgpkgBundle)
					return false
				}

				craneManifests := &struct {
					Manifests []struct {
						MediaType string `yaml:"mediaType"`
						Digest    string `yaml:"digest"`
						Size      int    `yaml:"size"`
						Platform  struct {
							Architecture string `yaml:"architecture"`
							Os           string `yaml:"os"`
						} `yaml:"platform"`
					} `yaml:"manifests"`
				}{}

				// for all images in the bundle, get their manifests
				for _, image := range imgpkgDescribe.Content.Images {
					cmd := exec.Command("crane", "manifest", image.Image)
					output, err := cmd.CombinedOutput()
					if err != nil {
						logrus.Errorf("Failed to get crane manifest for %s (bundle %s): %s: %s (%s)", image.Image, imgpkgBundle, err, output, strings.Join(cmd.Args, " "))
						logrus.Errorf(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests" unsuccessful for %s`, imgpkgBundle)
						return false
					}

					err = yaml.Unmarshal(output, craneManifests)
					if err != nil {
						logrus.Errorf("Failed to unmarshal crane manifest output for %s (bundle %s): %s", image.Image, imgpkgBundle, err)
						logrus.Errorf(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests" unsuccessful for %s`, imgpkgBundle)
						return false
					}

					if len(craneManifests.Manifests) > 0 {
						bytes, _ := json.MarshalIndent(craneManifests.Manifests, "  ", "  ")
						logrus.Errorf("Manifests found for %s (bundle %s): %s", image.Image, imgpkgBundle, string(bytes))
						logrus.Errorf(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests" unsuccessful for %s`, imgpkgBundle)
						return false
					}
				}

				logrus.Infof(`Validation "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests" successful for %s`, imgpkgBundle)
				return true
			})
			if err != nil {
				return fmt.Errorf(`Failed to add custom validation for "{spec.template.spec.fetch[0].imgpkgBundle.image} has no manifests": %s`, err)
			}

			// register custom validation for "{spec.template.spec.template.kbld.paths} has imgpkg entry"
			err = validate.RegisterValidation("kbld-paths", func(fl validator.FieldLevel) bool {
				len := fl.Field().Len()
				paths := fl.Field().String()

				if len == 0 { // hack for list-based validator
					return true
				} else { // check for imagelock entry
					for i := 0; i < len; i++ {
						if fl.Field().Index(i).String() == ".imgpkg/images.yml" {
							logrus.Infof(`Validation "{spec.template.spec.template.kbld.paths} has imgpkg entry" successful for %s`, paths)
							return true
						}
					}
				}

				logrus.Errorf(`Validation "{spec.template.spec.template.kbld.paths} has imgpkg entry" unsuccessful for %s`, paths)
				return false
			})
			if err != nil {
				return fmt.Errorf(`Failed to add custom validation for "{spec.template.spec.template.kbld.paths} has imgpkg entry": %s`, err)
			}

			// read file and test
			fileBytes, err := os.ReadFile(packageCR)
			if err != nil {
				return fmt.Errorf("Failed to read file %s: %s", packageCR, err)
			}
			err = yaml.Unmarshal(fileBytes, fields)
			if err != nil {
				return fmt.Errorf("Failed to unmarshal file %s: %s", packageCR, err)
			}
			err = validate.Struct(fields)
			if err != nil {
				return fmt.Errorf("Failed to validate YAML fields for %s: %s", packageCR, err)
			}

			logrus.Infof("%s passed for %s", component, packageCR)
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidatePackageMetadataCR() error {
	for component, packageMetadataCR := range packageMetadataCRs {
		err := func() error {
			fields := &struct {
				APIVersion string `yaml:"apiVersion" validate:"required,eq=data.packaging.carvel.dev/v1alpha1"`
				Kind       string `yaml:"kind" validate:"required,eq=PackageMetadata"`
				Metadata   struct {
					Name        string   `yaml:"name" validate:"required"`
					Annotations struct{} `yaml:"annotations"`
				} `yaml:"metadata" validate:"required"`
				Spec struct {
					DisplayName        string        `yaml:"displayName" validate:"required"`
					LongDescription    string        `yaml:"longDescription" validate:"required"`
					ShortDescription   string        `yaml:"shortDescription" validate:"required"`
					Categories         []interface{} `yaml:"categories"`
					ProviderName       string        `yaml:"providerName" validate:"required,eq=VMware"`
					SupportDescription string        `yaml:"supportDescription" validate:"required"`
					IconSVGBase64      string        `yaml:"iconSVGBase64" validate:"omitempty,base64"`
					Maintainers        []struct {
						Name string `yaml:"name" validate:"required"`
					} `yaml:"maintainers" validate:"required,dive"`
				} `yaml:"spec" validate:"required"`
			}{}

			// read file and test
			fileBytes, err := os.ReadFile(packageMetadataCR)
			if err != nil {
				return fmt.Errorf("Failed to read file %s: %s", packageMetadataCR, err)
			}
			err = yaml.Unmarshal(fileBytes, fields)
			if err != nil {
				return fmt.Errorf("Failed to unmarshal file %s: %s", packageMetadataCR, err)
			}
			err = validator.New().Struct(fields)
			if err != nil {
				return fmt.Errorf("Failed to validate YAML fields for %s: %s", packageMetadataCR, err)
			}

			logrus.Infof("%s passed for %s", component, packageMetadataCR)
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidateAnnotationSize() error {
	values := struct {
		Metadata struct {
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"metadata"`
	}{}

	const TotalAnnotationSizeLimitB int = 256 * (1 << 10) // 256 kB

	for component, packageCR := range packageCRs {
		err := func() error {
			var packageCRYAMLBytes []byte
			var err error

			packageCRYAMLBytes, err = os.ReadFile(packageCR)
			if err != nil {
				return fmt.Errorf("Failed to read file %s: %s", packageCR, err)
			}

			err = yaml.Unmarshal(packageCRYAMLBytes, &values)
			if err != nil {
				return fmt.Errorf("Failed to unmarshal file %s: %s", packageCR, err)
			}

			// check total size limits
			// ref: https://github.com/kubernetes/kubernetes/blob/bdf34b3f56d269d9b435a882145aa7fe217691ce/staging/src/k8s.io/apimachinery/pkg/api/validation/objectmeta.go#L58-L67
			var totalSize int64
			for k, v := range values.Metadata.Annotations {
				totalSize += (int64)(len(k)) + (int64)(len(v))
			}
			if totalSize > (int64)(TotalAnnotationSizeLimitB) {
				return fmt.Errorf("failed to validate annotation size for %s at %s: annotations size %f kB is larger than limit %d kB", component, packageCR, float64(totalSize)/(1<<10), TotalAnnotationSizeLimitB/(1<<10))
			} else {
				logrus.Infof("validation successful for %s at %s: annotations size %f kB is smaller than limit %d kB", component, packageCR, float64(totalSize)/(1<<10), TotalAnnotationSizeLimitB/(1<<10))
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}
