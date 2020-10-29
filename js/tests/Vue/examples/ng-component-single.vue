<template>
    <p v-html="var"/>
    <p v-html="変数"/>
    <p v-html="var2"/>
    <p v-html="varTemp"/>
    <p v-html="mod"/>
    <p v-html="mod2"/>
    <p v-html="varComp"/>
    <p v-html="varComp2"/>
    <p v-html="funcVar"/>
    <p v-html="hello"/>
</template>
<script>
  const v = window.location.hash;
  var v2 = v;
  const str = `hash: ${window.location.hash}`;
  const mod = require('test');
  const x2 = null || undefined || window.location.hash || "hoge";
  export default {
    data: function() {
      return {
        var: v,
        "変数": v2,
        var2: undefinedVar,
        varTemp: str,
        mod: mod,
        mod2: require('test')(),
        varComp: window.location.hash || "hoge",
        varComp2: x2,
        funcVar: (()=>{return window.location.hash;})(),
      }
    },
    computed: {
      hello() {
        return v2;
      },
    }
  }
</script>
<style>
</style>