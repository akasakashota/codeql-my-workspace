# Use v-html directive
v-html ディレクティブに変数をバインドしています。 その変数が外部から制御可能な場合にXSS が発生する可能性があります。

その変数が外部から制御不可能なものであるか、もしくは適切にエスケープ処理されているかを確認してください。


## Recommendation
v-html にバインドする値は、外部から制御不可能なものを利用するようにしてください。


## Example

```html
<template>
  <p v-html="safe" />
  <p v-html="danger" />
</template>
<script>
export default {
  data: function () {
    return {
      // Safe: not controllable by user
      safe: "<b>test</b>",
      // Bad: may be controllable by user
      danger: window.location.hash,
    };
  },
};
</script>
<style>
</style>
```

## References
* Vuejs: [セキュリティ](https://jp.vuejs.org/v2/guide/security.html)
* OWASP: [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
* OWASP [DOM Based XSS](https://www.owasp.org/index.php/DOM_Based_XSS).
* OWASP [Types of Cross-Site Scripting](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting).
* Wikipedia: [Cross-site scripting](http://en.wikipedia.org/wiki/Cross-site_scripting).
* Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
* Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
* Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
* Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
