# WPU Contact Forms ZohoCRM

Link WPUContactForms results to Zoho CRM

[![PHP workflow](https://github.com/WordPressUtilities/wpucontactforms_zohocrm/actions/workflows/php.yml/badge.svg 'PHP workflow')](https://github.com/WordPressUtilities/wpucontactforms_zohocrm/actions)

## How to use :

- Configure the plugin with a client ID and a client Secret.
- Install WPUContactForms & create a form.
- Add a `zohocrm_field_name` attribute to each field you wish to zend into Zoho CRM.

### Example :

```php
$fields['contact_name'] = array(
    'zohocrm_field_name' => 'Last_Name',
    'autocomplete' => 'familyname',
    'label' => 'Name',
    'required' => 1
);
```
