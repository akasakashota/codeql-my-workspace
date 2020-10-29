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