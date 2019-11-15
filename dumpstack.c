void dumpStack(lua_State* L)
{
  int i;
  //スタックに積まれている数を取得する
  int stackSize = lua_gettop(L);
  for( i = stackSize; i >= 1; i-- ) {
    int type = lua_type(L, i);
    printf("Stack[%2d-%10s] : ", i, lua_typename(L,type) );

    switch( type ) {
    case LUA_TNUMBER:
      //number型
      printf("%f", lua_tonumber(L, i) );
      break;
    case LUA_TBOOLEAN:
      //boolean型
      if( lua_toboolean(L, i) ) {
        printf("true");
      }else{
        printf("false");
      }
      break;
    case LUA_TSTRING:
      //string型
      printf("%s", lua_tostring(L, i) );
      break;
    case LUA_TNIL:
      //nil
      break;
    default:
      //その他の型
      printf("%s", lua_typename(L, type));
      break;
    }
    printf("¥n");
  }
  printf("¥n");
}
