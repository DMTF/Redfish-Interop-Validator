---
DocTitle: Redfish Interoperability Profiles
DocNumber: '0272'
DocClass: Normative
DocVersion: '0.95.0'
modified: '2017-6-30'
status: work in progress
released: false
copyright: '2017'
---

# Redfish Interoperability Profiles

## Introduction

Because the Redfish Schemas are designed to provide signifcant flexibility, and allow conforming implementations on a wide variety of products, very few properties within the Schemas are required by the Specification.  But consumers and software developers need a more rigidly defined set of required properties (features) in order to accomplish management tasks.  This set allows users to compare implementations, specify needs to vendors, and allows software to rely on the availability of data.  To provide that "common ground", a Redfish Interoperabilty Profile allows the definition of a set of schemas and property requirements, which meet the needs of a particluar class of product or service.

The Redfish Interoperability Profile is a JSON document which contains Schema-level, Property-level, and Registry-level requirements.  At the property level, these requirements can include a variety of ConditionalRequirements under which the requirement applies.

## Design Tenets

All profile entries (at the Profile, Resource, or Property level) are "additive".  That is, each requirement can only apply more rigid requirements which override less rigid requirements.

The profile document is a JSON document designed to minimize the work necessary to define a profile, by defining default values that allow the majority of requirements to be stated with minimal effort.    

The JSON document structure is intended to align easily with JSON payloads retreived from Redfish Service implementations, to allow for easy comparisons and conformance testing. 

Profile requirements do not allow for exclusions of data.  Implementations are able to provide more data in their resources than required by a profile, as an implementation likely addresses multiple use cases or Profiles.  This include both standard properties and OEM extensions.
   
## Profile Definition

A Redfish Interoperability Profile is specified in a JSON document.  The JSON objects and properties contained in the document are described in this specification, and are also available in a json-schema form (RedfishInteroperabilityProfile.v1_x_x.json) from the DMTF's Redfish Schema repository at http://redfish.dmtf.org/profiles for download.  The json-schema can be used to validate a Profile document to ensure compatibility with automated conformance tools or utilities.

### Basic functions

At the top level of the JSON document are the basic properties which describe the profile, including authorship and contact information, versioning, and other profiles to include in order to build upon previous work.

| property | type | description | 
| --- | --- | --- |
| SchemaDefinition | string | The JSON schema which defines this Redfish Interoperability Profile document and can be used to validate its contents. |
| ProfileName | string | The name of this Redfish Profile. |
| Author | string | The author(s) of this Redfish Profile. |
| ProfileVersion | string | The version of this Redfish Profile. |
| Purpose | string | A description of the purpose of this Redfish Profile, such as its intended target audience, product segments, etc.|
| ContactInfo | string | An email address that can be used to provide feedback about this Redfish Profile. |
| RequiredProfiles | object | A set of Redfish Profiles which serve as a basis for this Profile.  The requirements set forth in these Profiles are included in this Profile. |

#### Required Profiles

The RequiredProfiles object contains properties (of type object) that are named to match the name of the profile to be included.  Each of these sub-objects contains the properties listed below.

| property | type | description | 
| --- | --- | --- |
| Repository | string | A URI providing the location of the repository which contains the file(s) to be included.  If absent, the location shall be the Redfish Schema Repository at redfish.dmtf.org |
| OwningEntity | string | Indicates whether this resource is defined by schema published by a standards body or an OEM. If this property is absent, the value shall be 'DMTF'.The author(s) of this Redfish Profile. |
| OwningEntityName | string | Name of the owning entity, when used with 'Other', follows 'Oem Property Naming' in the Redfish Specification |
| MinVersion | string | The minimum version required by this Redfish Profile. If this property is absent, the minimum value shall be '1.0.0'.|

### Example

The following is an example of the top-level properties in a Profile, with two Required profiles included.

~~~
	"@odata.type": "RedfishProfile.v1_0_0.RedfishProfile",
	"ProfileName": "Anchovy",
	"Version": "1.0.2",
	"Author": "Pizza Box Project",
	"Purpose": "This is a sample Redfish Interoperability profile.",
	"ContactInfo": "pizza@contoso.com",
	"RequiredProfiles": {
		"DMTFBasic": {
			"MinVersion": "1.0.0"
		},
		"ContosoPizza": {
			"OwningEntity": "Other",
			"OwningEntityName": "Contoso",
			"Repository": "contoso.com/profiles",
			"MinVersion": "1.0.0"
		}
	}
~~~

### Protocol requirements

An object named 'Protocol' contains properties which describe Redfish protocol functionality that is not related to the supported schemas or properties.  Therefore, these functions cannot be validated by comparing retreived JSON payloads.

| property | type | description | 
| --- | --- | --- |
| MinVersion | string |  The minimum version of the Redfish Specification protocol support required by this Profile. This version shall be reported by the Redfish Service in the ServiceRoot property 'RedfishVersion'.  If this property is absent, the minimum value shall be '1.0.0'. |
| DiscoveryRequired | boolean | Indicates that support of the Redfish SSDP Discovery protocol is required for this Profile. If this property is absent, the value shall be false. |

### Example 

~~~
	"Protocol": {
		"MinVersion": "1.2",
		"DiscoveryRequired": true
	}
~~~

## Resource (Schema) requirements

The primary content in a Redfish Profile is the set of supported property requirements.  As Redfish is organized and defined by schema-backed JSON resources, these requirements are also organized by schema.

For each schema, an object is created in the JSON document, named to match the schema's name.  Within this object, properties describe the location of the schema file, and schema-level requirements.  Within each schema-level object is a "PropertyRequirements" object that describes the property-level requirements for that schema.  The definition of both the schema/resource-level and property-level requirements are accomplished using the same mechanisms, which are described in the next section.  

The structure of the resource and property requirements is:
~~~
{
    <Schema Name>: {
       "MinVersion": "<version>"
	   "PropertyRequirements": {
		   <Property Name>: { 
		      <Requirements for this property>
		   },
		   <Property Name>: {
		   }
		},
		"ActionRequirements": {
		   <Action Name>: {
		      <Requirements for this action>
		   }
		}
    },
	<Additional Schemas...>
~~~

### Schema level functions

The following options are available at the schema level:

| property | type | description | 
| --- | --- | --- |
| Repository | string | A URI providing the location of the repository which contains the file(s) to be included.  If absent, the location shall be the Redfish Schema Repository at redfish.dmtf.org |
| OwningEntity | string | Indicates whether this resource is defined by schema published by a standards body or an OEM. If this property is absent, the value shall be 'DMTF'.The author(s) of this Redfish Profile. |
| OwningEntityName | string | Name of the owning entity, when used with 'Other', follows 'Oem Property Naming' in the Redfish Specification |
| MinVersion | string | The minimum version required by this Redfish Profile. If this property is absent, the minimum value shall be '1.0.0'.|
| ReadRequirement | string | Resource-level requirement for this schema, see [ReadRequirement](#readrequirement) section. |
| Purpose | string | A description of the purpose of this requirement.  This text can provide justification or reasoning behind the requirement for use in the profile documentation. |
| ConditionalRequirements | object | Resource-level conditional requirements that apply to instances of this schema, see [Conditional Requirements](#conditional-requirements) section. |

#### Example

This example shows a simple required schema 
~~~
	"ComputerSystem": {
		"MinVersion": "1.2.0",
		"Purpose": "Every instance must have a logical-view ComputerSystem resource.",
		"PropertyRequirements": {
			"SerialNumber": {},
			"Manufacturer": {},
			"Model": {
				"ReadRequirement": "Recommended"
			},
~~~

### Property level functions

Within the 'PropertyRequirements' object are additional objects which are named to match the property name in the parent object's schema definition.  This object then contains the property-level requirements, which account for the bulk of a Profile's definition.  One additional level of JSON objects may be embedded, essentially nesting a 'PropertyRequirements' object.

The following options are available at the property level:

| property | type | description | 
| --- | --- | --- |
| ReadRequirement | string | Property-level requirement for this property, see [ReadRequirement](#readrequirement) section. |
| WriteRequirement | string | Property-level write (HTTP PATCH or PUT) requirement for this property, see [WriteRequirement] (#writerequirement) section. |
| ConditionalRequirements | object | Property-level conditional requirements that apply to instances of this property, see [Conditional Requirements](#conditional-requirements) section. |
| MinCount | integer | For array type properties, the minimum number of non-NULL instances within the array. |
| MinSupportValues |  array | The minimum set of enumerations that must be supported for this writable property. |
| Comparison | string | The condition used to compare the value of the property to 'Values'. See the [Comparison](#comparison) section. |
| Purpose | string | A description of the purpose of this requirement.  This text can provide justification or reasoning behind the requirement for use in the profile documentation. |
| Values | array | The value(s) required for this property based on the 'Comparison'. If no 'Comparison' is present, the property must be equal to one of the values listed. |
| PropertyRequirements | object | For Redfish properties of type 'object', this object contains requirements for the properties contained within the specified object. This specification allows for only one level of nested objects and requirements.|

#### Example

This example shows property-level requirements, including one of type 'object' containing further requirements on that object's properties.  For each 'Power' resource, the 'PowerSupplies' and 'Voltages' array properties are required.  'Voltages' has no further requirements (by default, this property is mandatory, and as an array type, must have at least one item in the array. The 'PowerSupplies' array must contain at least two (object) items.  Within the array, at least one item's 'PowerSupplyType' property must have a value of 'AC' or 'DC'.

~~~
	"Power": {
		"PropertyRequirements": {
			"PowerSupplies": {
				"ReadRequirement": "Mandatory",
				"MinCount": 2,
				"PropertyRequirements": {
					"Status": {},
					"PowerSupplyType": {
						"ReadRequirement": "AnyOf",
						"Purpose": "Need to know AC vs. DC supplies to match input readings to expected values.",
						"Values": [ "AC", "DC" ]
					},
					"LineinputVoltage": {},
					"PowerCapacityWatts": {},
					"InputRanges": {
						"ReadRequirement": "Recommended"
					}
				}
			},
			"Voltages": {}
		}
	},
~~~		

#### Comparison

The Comparison function uses the following enumerations to represent the arithmetic comparisons available:

| value | description |
| --- | --- |
| Absent | The property is not present in this resource. |
| AnyOf | An instance of the property in this resource must be equal to one of the values listed. |
| AllOf | At least one instance of the property in this resource must be equal to each of the values listed. |
| Equal | The value must be equal to the KeyValue. |
| NotEqual | The value of the property must not be equal to the value(s) listed. |
| GreaterThan | The value of the property must be greater than the Values. |
| GreaterThanEqual | The value of the property must be greater than or equal to the Values. |
| LessThan | The value of the property must be less than to the Values. |
| LessThanEqual | The value of the property must be less than or equal to the Values. |
| Present | The property is present in this resource. |


#### ReadRequirement

This function specifies the level of basic read (HTTP GET) requirement applied to the resource or property.  The default value, or if no 'ReadRequirement' is present, is 'Mandatory'. For properties of type 'object', requirements of the embedded properties will apply only if the object is present.

| value | description |
| --- | --- |
| Mandatory |  This property is required in all instances of this resource. For properties of type 'array', the property is required in all non-NULL array items. If 'Values' are listed, at least one instance of each enumeration value is required among instance(s) of this property.|
| Recommended | It is recommended, but not required, that this property be supported. |
| IfImplemented | This property is required if the underlying functionality is implemented. For properties of type 'object', requirements on embedded properties within the object will only apply if the object is present. |
| Conditional | This property is only required if 'ConditionalRequirements' items apply to this instance of the resource. |
| None | This property is not required by this profile.  It is listed here for clarity. |

#### WriteRequirement

This function specifies the level of write support (HTTP PATCH or PUT) applied to a property.  The default value, or if no 'WriteRequirement' is present, is 'None'.  

| value | description |
| --- | --- |
| Mandatory |  This property is required to be writable in all instances of this resource. |
| Recommended | It is recommended, but not required, that this property be writable. |
| None | This property is not required to be writable by this profile.  It is listed here for clarity, and is the default value used if 'WriteRequirement' is not present. |


#### Conditional Requirements

The most flexible aspect of the Redfish Profile definition is the ability to make resource or property-level requirements that are dependent on one or more ConditionalRequirements within the resource and the parent resource(s) in the resource tree.

The 'ConditionalRequirements' array function specifies these conditional requirements, which add to any requirements also defined for the resource or property.  Note that a condition cannot override or weaken a requirement already specified.  For example, if a property requirement is marked as 'Mandatory', no conditional requirement could mark the property as 'None'.  Instead, the property would be specified with a 'None' requirement, and with one or more ConditionalRequirements that would specify when the property requirement becomes 'Mandatory'.

The following options are available for each conditional requirement:

| property | type | description | 
| --- | --- | --- |
| ReadRequirement | string | The requirement to apply to the resource or property if the condition is met.|
| WriteRequirement | string | Property-level write (HTTP PATCH or PUT) requirement for this property, see [WriteRequirement] (#writerequirement) section. |
| Purpose | string | Text describing the purpose of this conditional requirement. |
| SubordinateToResource | array | An ordered list (from top of heirarchy to bottom) of resources where this resource is linked as as subordinate resource.  The conditional requirements listed for the resource apply only to instances which are subordinate to the listed parent resource list.  See [Parent and subordinate resources](#parent-and-subordinate-resources) section. |
| CompareProperty | string | The name of the property in this resource whose value is used to test this condition. The property name will be evaluated at the current object level within the resource.  If the property name is not found at the current level, upper levels will be searched until the root level is reached. See the [Compare Property](#compare-property) section.|
| CompareValues | array | Values of the CompareProperty used to test this condition. See the [Compare Property](#compare-property) section. |
| Comparison | string | The condition used to compare the value of the property named by 'CompareProperty' to the value of 'CompareValues'.  If the comparison is true, then this conditional requirement applies. See the [Compare Property](#compare-property) section. |


##### Parent and subordinate resources

As there can be several instances of a particular Redfish schema in the resource tree, the requirements placed on those resources may vary depending on their usage.  Since the Profile is schema-centric, the 'SubordinateToResource' function allows a Profile to specify requirements based a resource instance's placement in the resource tree.

'SubordinateToResource' allows specifying the schema (resource) path from parent resources to the resource to which the requirements apply.  This property contains an array of schema names, in the top-down order that they appear in the path to the required resource.

###### Example

For the property 'HostName' in the 'EthernetInterface' schema, the example shows it as 'Recommended' property.  But if an instance of 'EthernetInterface' is linked from a 'ComputerSystem' resource, through the 'EthernetInterfaceCollection', then the 'Condition' is met, which changes the 'HostName' property requirement to 'Mandatory'.

In the second part of the example, the 'IPv6Addresses' array property is required to have at least one item ('MinCount') in the array.  But if, as above, the instance is subordinate to a 'ComputerSystem' (and 'EthernetInterfaceCollection') resource, then at least two items are required in the array.

~~~
	"EthernetInterface": {
		"PropertyRequirements": {
			"HostName": {
				"ReadRequirement": "Recommended",
				"WriteRequirement": "Recommended",
				"ConditionalRequirements": [{
					"SubordinateToResource": ["ComputerSystem", "EthernetInterfaceCollection"],
					"ReadRequirement": "Mandatory",
					"Purpose": "Host Name is used to match this instance to other data sources.",
				}]
			},
			"IPv6Addresses": {
				"ReadRequirement": "Mandatory",
				"MinCount": 1,
				"ConditionalRequirements": [{
					"SubordinateToResource": ["ComputerSystem", "EthernetInterfaceCollection"],
					"MinCount": 2
				}]
			}
		}
	}
~~~

##### Compare Property

A typical need for a conditional requirement is a dependency on the value of another property within the resource.  This type of dependency can be used when several different product variations share a common schema definition.  In that case, Redfish schemas normally define a type-specifying property with enumerations (for a variety of product categories) that can be used to differentiate Profile requirements by product category.

To accomplish this, there are three Profile properties related to this function:

| property | type | description | 
| --- | --- | --- |
| CompareProperty | string | The name of the property in this resource whose value is used to test this condition. The property name will be evaluated at the current object level within the resource.  If the property name is not found at the current level, upper levels will be searched until the root level is reached.|
| Comparison | string |The condition used to compare the value of the property named by 'CompareProperty' to the value of 'Values'.  If the comparison is true, then this conditional requirement applies.|
| CompareValues | array | Values of the CompareProperty used to test this condition. |


##### Example

This example shows a CompareProperty condition applied to the 'IndicatorLED' property, which has a base 'Recommended' requirement, but becomes 'Mandatory' if the 'SystemType' property has a value of 'Physical' or 'Composed'.

~~~
	"IndicatorLED": {
		"ReadRequirement": "Recommended",
		"ConditionalRequirements": [{
			"Purpose": "Physical and composed Systems must have a writable Indicator LED",
			"CompareProperty": "SystemType",
			"Comparison": "AnyOf",
			"CompareValues": ["Physical", "Composed"],
			"ReadRequirement": "Mandatory",
			"WriteRequirement": "Mandatory"
		}]
	},
~~~

### Action Requirements

As several critical functions of a Redfish Service are implemented as 'Actions', the Profile may place requirements for support of these Actions.  The requirements can which Parameters must be supported, and may specify Allowable Values for those parameters.

The following functions are available to specify requirements for an Action within a Resource requirement:

| property | type | description | 
| --- | --- | --- |
| ReadRequirement | string | The requirement to apply to this Action.|
| Parameters | object | Requirements for any parameter available for this Action. |
| Purpose | string | A description of the purpose of this requirement.  This text can provide justification or reasoning behind the requirement for use in the profile documentation. |

#### Parameters

The following functions are available to specify requirements for a parameter on a particular Action:

| property | type | description | 
| --- | --- | --- |
| ReadRequirement | string | The requirement to apply to this parameter.|
| MinSupportValues | array | The minimum set of enumerations that must be supported for this parameter. |

#### Example

This exampls shows the 'Reset' action as required for this resource, along with the required parameter 'ResetType', which must support the values of 'ForceOff' and 'PowerCycle'.

~~~
	"ActionRequirements": {
		"Reset": {
			"ReadRequirement": "Mandatory",
			"Purpose": "Ability to reset the unit is a core requirement of most users.",
			"Parameters": {
				"ResetType": {
					"MinSupportValues": ["ForceOff", "PowerCycle"],
					"ReadRequirement": "Mandatory"
				}
			}
		}
	}
~~~			
			
## Registry level requirements

While not normally part of the JSON resources, the Redfish-defined Message Registries are important for interoperability, as they indicate what functionality has been implemented for Events, and are also a useful method for setting expections on the use of Extended Info error messages when interacting with a Redfish Service implementation.

The following functions are available to specify Registry-level requiremenets:

| property | type | description | 
| --- | --- | --- |
| Repository | string | A URI providing the location of the repository which contains the file(s) to be included.  If absent, the location shall be the Redfish Schema Repository at redfish.dmtf.org |
| OwningEntity | string | Indicates whether this resource is defined by schema published by a standards body or an OEM. If this property is absent, the value shall be 'DMTF'.The author(s) of this Redfish Profile. |
| OwningEntityName | string | Name of the owning entity, when used with 'Other', follows 'Oem Property Naming' in the Redfish Specification |
| MinVersion | string | The minimum version required by this Redfish Profile. If this property is absent, the minimum value shall be '1.0.0'.|
| ReadRequirement | string | Resource-level requirement for this Registry, see [ReadRequirement](#readrequirement) section. |
| Purpose | string | A description of the purpose of this requirement.  This text can provide justification or reasoning behind the requirement for use in the profile documentation. |
| Messages | object | The Messages in this Registry which have support requirements for this Redfish Profile. If this property is absent, all Messages in this Registry follow the registry-level 'ReadRequirement'. |

### Messages

Within the Registry object are additional objects which are named to match the Message name in the Registry definition.  This object then contains the message-level requirements.

The following options are available at the property level:

| property | type | description | 
| --- | --- | --- |
| ReadRequirement | string | Message-level requirement for this Message, see [ReadRequirement](#readrequirement) section. |


### Example

This example shows requirements for two Message Registries, including one OEM-defined registry.  The 'Base' Registry is a DMTF standard Registry (by default since no 'OwningEntity' is listed) and therefor can be retreieved by default from the DMTF Repository. The 'Base' Registry lists only four Messages that are required. 

In the case of the OEM-defined Registry 'ContosoPizzaMessages', the 'Mandatory' requirement set at the Registry level specifies that all Messages defined in that Registry are required.

~~~
	"Registries": {
		"Base": {
			"MinVersion": "1.1.0",
			"Messages": {
				"Success": {},
				"GeneralError": {},
				"Created": {},
				"PropertyDuplicate": {}
			}
		},
		"ContosoPizzaMessages": {
			"OwningEntity": "Other",
			"OwningEntityName": "Contoso",
			"Repository": "contoso.com/registries",
			"ReadRequirement": "Mandatory"
		}
	}
~~~
	
# Change Log

| version | date | changes |
| --- | --- | --- |
| v0.9 | 5-14-17 | Work In Progress release. |
