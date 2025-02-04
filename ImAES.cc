#include "ImAES.h"
#include <string.h>
#include <netinet/in.h>

sv ImAES::mxor(uc *target, cuc *src, int len){
  while ( len-- )
  {
    *target++ ^= *src++;
  }
}

sv ImAES::rot_word(uc *w){
  unsigned char tmp;
  
  tmp = w[ 0 ];
  w[ 0 ] = w[ 1 ];
  w[ 1 ] = w[ 2 ];
  w[ 2 ] = w[ 3 ];
  w[ 3 ] = tmp;
}

sv ImAES::sub_word(uc *w){
  int i = 0;
  
  for ( i = 0; i < 4; i++ )
  {
    w[ i ] = sbox[ ( w[ i ] & 0xF0 ) >> 4 ][ w[ i ] & 0x0F ];
  } 
}

sv ImAES::compute_key_schedule(cuc *key, int key_length, uc w[][4]){
  int i;
  int key_words = key_length >> 2;
  unsigned char rcon = 0x01;
  
  // First, copy the key directly into the key schedule
  memcpy( w, key, key_length );
  for ( i = key_words; i < 4 * ( key_words + 7 ); i++ )
  {
    memcpy( w[ i ], w[ i - 1 ], 4 );
    if ( !( i % key_words ) )
    {
      rot_word( w[ i ] );
      sub_word( w[ i ] );
      if ( !( i % 36 ) )
      {
        rcon = 0x1b;
      }
      w[ i ][ 0 ] ^= rcon;
      rcon <<= 1;
    }
    else if ( ( key_words > 6 ) && ( ( i % key_words ) == 4 ) )
    {
     sub_word( w[ i ] );  
    }
    w[ i ][ 0 ] ^= w[ i - key_words ][ 0 ];
    w[ i ][ 1 ] ^= w[ i - key_words ][ 1 ];
    w[ i ][ 2 ] ^= w[ i - key_words ][ 2 ];
    w[ i ][ 3 ] ^= w[ i - key_words ][ 3 ];
  }
}

sv ImAES::add_round_key(uc state[][4], uc w[][4]){
  int c, r;

  for ( c = 0; c < 4; c++ )
  {
    for ( r = 0; r < 4; r++ )
    {
      state[ r ][ c ] = state[ r ][ c ] ^ w[ c ][ r ];
    }
  }
}

sv ImAES::sub_bytes(uc state[][4]){
  int r, c;

  for ( r = 0; r < 4; r++ )
  {
    for ( c = 0; c < 4; c++ )
    {
      state[ r ][ c ] = sbox[ ( state[ r ][ c ] & 0xF0 ) >> 4 ]
                            [ state[ r ][ c ] & 0x0F ];
    }
   }
}

sv ImAES::shift_rows(uc state[][4]){
  int tmp;

  tmp = state[ 1 ][ 0 ];
  state[ 1 ][ 0 ] = state[ 1 ][ 1 ];
  state[ 1 ][ 1 ] = state[ 1 ][ 2 ];
  state[ 1 ][ 2 ] = state[ 1 ][ 3 ];
  state[ 1 ][ 3 ] = tmp;

  tmp = state[ 2 ][ 0 ];
  state[ 2 ][ 0 ] = state[ 2 ][ 2 ];
  state[ 2 ][ 2 ] = tmp;
  tmp = state[ 2 ][ 1 ];
  state[ 2 ][ 1 ] = state[ 2 ][ 3 ];
  state[ 2 ][ 3 ] = tmp;

  tmp = state[ 3 ][ 3 ];
  state[ 3 ][ 3 ] = state[ 3 ][ 2 ];
  state[ 3 ][ 2 ] = state[ 3 ][ 1 ];
  state[ 3 ][ 1 ] = state[ 3 ][ 0 ];
  state[ 3 ][ 0 ] = tmp;
}

uc ImAES::xtime(uc c){
  return ( c << 1 ) ^ ( ( c & 0x80 ) ? 0x1b : 0x00 );
}

uc ImAES::dot(uc x, uc y){ 
  unsigned char mask; 
  unsigned char product = 0; 
  
  for ( mask = 0x01; mask; mask <<= 1 )
  {
    if ( y & mask ) 
    {
      product ^= x; 
    }
    x = xtime( x );
   }

 return product;
}

sv ImAES::mix_columns(uc s[][4]){
  int c;
  unsigned char t[ 4 ];
 
  for ( c = 0; c < 4; c++ )
  {
    t[ 0 ] = dot( 2, s[ 0 ][ c ] ) ^ dot( 3, s[ 1 ][ c ] ) ^ 
             s[ 2 ][ c ] ^ s[ 3 ][ c ];
    t[ 1 ] = s[ 0 ][ c ] ^ dot( 2, s[ 1 ][ c ] ) ^ 
             dot( 3, s[ 2 ][ c ] ) ^ s[ 3 ][ c ];
    t[ 2 ] = s[ 0 ][ c ] ^ s[ 1 ][ c ] ^ dot( 2, s[ 2 ][ c ] ) ^ 
             dot( 3, s[ 3 ] [ c ] );
    t[ 3 ] = dot( 3, s[ 0 ][ c ] ) ^ s[ 1 ][ c ] ^ s[ 2 ][ c ] ^ 
             dot( 2, s[ 3 ][ c ] );
    s[ 0 ][ c ] = t[ 0 ];
    s[ 1 ][ c ] = t[ 1 ];
    s[ 2 ][ c ] = t[ 2 ];
    s[ 3 ][ c ] = t[ 3 ];
  }
}

sv ImAES::aes_block_encrypt(cuc *input_block, uc *output_block, cuc *key, int key_size){
  int r, c;
  int round;
  int nr;
  unsigned char state[ 4 ][ 4 ];
  unsigned char w[ 60 ][ 4 ];

  for ( r = 0; r < 4; r++ )
  {
    for ( c = 0; c < 4; c++ )
    {
      state[ r ][ c ] = input_block[ r + ( 4 * c ) ];
    }
  }
  // rounds = key size in 4-byte words + 6
  nr = ( key_size >> 2 ) + 6;
  
  compute_key_schedule( key, key_size, w );
  
  add_round_key( state, &w[ 0 ] );

  for ( round = 0; round < nr; round++ )
  {
    sub_bytes( state );
    shift_rows( state );
    if ( round < ( nr - 1 ) )
    {
      mix_columns( state );
    }
    add_round_key( state, &w[ ( round + 1 ) * 4 ] );
  }

  for ( r = 0; r < 4; r++ )
  { 
    for ( c = 0; c < 4; c++ )
    {
      output_block[ r + ( 4 * c ) ] = state[ r ][ c ];
    }
  }
}

sv ImAES::inv_shift_rows(uc state[][4]){ 
  int tmp;

  tmp = state[ 1 ][ 2 ];
  state[ 1 ][ 2 ] = state[ 1 ][ 1 ];
  state[ 1 ][ 1 ] = state[ 1 ][ 0 ];
  state[ 1 ][ 0 ] = state[ 1 ][ 3 ];
  state[ 1 ][ 3 ] = tmp;
 
  tmp = state[ 2 ][ 0 ];
  state[ 2 ][ 0 ] = state[ 2 ][ 2 ];
  state[ 2 ][ 2 ] = tmp;
  tmp = state[ 2 ][ 1 ];
  state[ 2 ][ 1 ] = state[ 2 ][ 3 ];
  state[ 2 ][ 3 ] = tmp;

  tmp = state[ 3 ][ 0 ];
  state[ 3 ][ 0 ] = state[ 3 ][ 1 ];
  state[ 3 ][ 1 ] = state[ 3 ][ 2 ];
  state[ 3 ][ 2 ] = state[ 3 ][ 3 ];
  state[ 3 ][ 3 ] = tmp;
}

sv ImAES::inv_sub_bytes(uc state[][4]){
  int r, c;

  for ( r = 0; r < 4; r++ )
  {
    for ( c = 0; c < 4; c++ )
    {
      state[ r ][ c ] = inv_sbox[ ( state[ r ][ c ] & 0xF0 ) >> 4 ]
                                [ state[ r ][ c ] & 0x0F ];
    }
  }
}

sv ImAES::inv_mix_columns(uc s[][4]){
  int c;
  unsigned char t[ 4 ];

  for ( c = 0; c < 4; c++ )
  {
    t[ 0 ] = dot( 0x0e, s[ 0 ][ c ] ) ^ dot( 0x0b, s[ 1 ][ c ] ) ^ 
             dot( 0x0d, s[ 2 ][ c ] ) ^ dot( 0x09, s[ 3 ][ c ] );
    t[ 1 ] = dot( 0x09, s[ 0 ][ c ] ) ^ dot( 0x0e, s[ 1 ][ c ] ) ^ 
             dot( 0x0b, s[ 2 ][ c ] ) ^ dot( 0x0d, s[ 3 ][ c ] );
    t[ 2 ] = dot( 0x0d, s[ 0 ][ c ] ) ^ dot( 0x09, s[ 1 ][ c ] ) ^ 
             dot( 0x0e, s[ 2 ][ c ] ) ^ dot( 0x0b, s[ 3 ][ c ] );
    t[ 3 ] = dot( 0x0b, s[ 0 ][ c ] ) ^ dot( 0x0d, s[ 1 ][ c ] ) ^ 
             dot( 0x09, s[ 2 ][ c ] ) ^ dot( 0x0e, s[ 3 ][ c ] );
    s[ 0 ][ c ] = t[ 0 ];
    s[ 1 ][ c ] = t[ 1 ];
    s[ 2 ][ c ] = t[ 2 ];
    s[ 3 ][ c ] = t[ 3 ];
  }
}

sv ImAES::aes_block_decrypt(cuc *input_block, uc *output_block, cuc *key, int key_size){
  int r, c;
  int round;
  int nr;
  unsigned char state[ 4 ][ 4 ];
  unsigned char w[ 60 ][ 4 ];

  for ( r = 0; r < 4; r++ )
  {
    for ( c = 0; c < 4; c++ )
    {
      state[ r ][ c ] = input_block[ r + ( 4 * c ) ];
    }
  }
  // rounds = key size in 4-byte words + 6
  nr = ( key_size >> 2 ) + 6;
 
  compute_key_schedule( key, key_size, w );
 
  add_round_key( state, &w[ nr * 4 ] );

  for ( round = nr; round > 0; round-- )
  {
    inv_shift_rows( state );
    inv_sub_bytes( state );
    add_round_key( state, &w[ ( round - 1 ) * 4 ] );
    if ( round > 1 )
    {
      inv_mix_columns( state );
    }
  }

  for ( r = 0; r < 4; r++ )
  { 
    for ( c = 0; c < 4; c++ )
    {
      output_block[ r + ( 4 * c ) ] = state[ r ][ c ];
    }
  }
}

sv ImAES::gf_multiply(cuc *X, cuc *Y, uc *Z){
  unsigned char V[ AES_BLOCK_SIZE ];
  unsigned char R[ AES_BLOCK_SIZE ];
  unsigned char mask;
  int i, j;
  int lsb;

  memset( Z, '\0', AES_BLOCK_SIZE );
  memset( R, '\0', AES_BLOCK_SIZE );
  R[ 0 ] = 0xE1;
  memcpy( V, X, AES_BLOCK_SIZE );
  for ( i = 0; i < 16; i++ )
  {
    for ( mask = 0x80; mask; mask >>= 1 )
    {
      if ( Y[ i ] & mask )
      {
        mxor( Z, V, AES_BLOCK_SIZE );
      }
 
      lsb = ( V[ AES_BLOCK_SIZE - 1 ] & 0x01 );
      for ( j = AES_BLOCK_SIZE - 1; j; j-- ) 
      {
        V[ j ] = ( V[ j ] >> 1 ) | ( ( V[ j - 1 ] & 0x01 ) << 7 );
      }
      V[ 0 ] >>= 1;

      if ( lsb )
      {
        mxor( V, R, AES_BLOCK_SIZE );
      }
    }
  }
}

sv ImAES::ghash(uc *H, uc *X, int X_len, uc *Y){
  unsigned char X_block[ AES_BLOCK_SIZE ];
  unsigned int input_len;
  int process_len;
  
  memset( Y, '\0', AES_BLOCK_SIZE );
  input_len = htonl( X_len << 3 ); // remember this for final block

  while ( X_len )
  {
    process_len = ( X_len < AES_BLOCK_SIZE ) ? X_len : AES_BLOCK_SIZE;
    memset( X_block, '\0', AES_BLOCK_SIZE );
    memcpy( X_block, X, process_len );
    mxor( X_block, Y, AES_BLOCK_SIZE );
    gf_multiply( X_block, H, Y );

    X += process_len;
    X_len -= process_len;
  }

  // Hash the length of the ciphertext as well
  memset( X_block, '\0', AES_BLOCK_SIZE );
  memcpy( X_block + 12, ( void * ) &input_len, sizeof( unsigned int ) );
  mxor( X_block, Y, AES_BLOCK_SIZE );
  gf_multiply( X_block, H, Y );
}

void ImAES::aes_ctr_encrypt(cuc *input, int input_len, uc *output, void *iv, cuc *key){
  unsigned char *nonce = ( unsigned char * ) iv;
  unsigned char input_block[ AES_BLOCK_SIZE ];
  unsigned int next_nonce;
  int block_size;

  while ( input_len )
  {
    block_size = ( input_len < AES_BLOCK_SIZE ) ? input_len : AES_BLOCK_SIZE;
    aes_block_encrypt( nonce, input_block, key, 16 );
    mxor( input_block, input, block_size );  // implement CTR
    memcpy( ( void * ) output, ( void * ) input_block, block_size );

    memcpy( ( void * ) &next_nonce, ( void * ) ( nonce + 12 ), 
      sizeof( unsigned int ) );
    // Have to preserve byte ordering to be NIST compliant
    next_nonce = ntohl( next_nonce );
    next_nonce++;
    next_nonce = htonl( next_nonce );
    memcpy( ( void * ) ( nonce + 12 ), ( void * ) &next_nonce, 
      sizeof( unsigned int ) );
    input += block_size;
    output += block_size;
    input_len -= block_size;
  } 
}

void ImAES::aes_cbc_mac(cuc *key, int key_length, cuc *text, int text_length, uc *mac){
  unsigned char input_block[ AES_BLOCK_SIZE ];
  unsigned char mac_block[ AES_BLOCK_SIZE ];

  memset( mac_block, '\0', AES_BLOCK_SIZE );

  while ( text_length >= AES_BLOCK_SIZE )
  {
    memcpy( input_block, text, AES_BLOCK_SIZE );
    mxor( input_block, mac_block, AES_BLOCK_SIZE );
    aes_block_encrypt( input_block, mac_block, key, key_length );
    text += AES_BLOCK_SIZE;
    text_length -= AES_BLOCK_SIZE;
  }

  memcpy( mac, mac_block, MAC_LENGTH );
}
int ImAES::aes_ccm_process(cuc *input, int input_len, cuc *addldata, unsigned short addldata_len, uc *output, void *iv, cuc *key, int decrypt){
  unsigned char nonce[ AES_BLOCK_SIZE ];
  unsigned char input_block[ AES_BLOCK_SIZE ];
  unsigned char mac_block[ AES_BLOCK_SIZE ];
  unsigned int next_nonce;
  int block_size;
  int process_len;
  unsigned int header_length_declaration;

  // The first input block is a (complicated) standardized header
  // This is just for the MAC; not output
  memset( input_block, '\0', AES_BLOCK_SIZE );
  input_block[ 0 ] = 0x1F;  // t = mac_length = 8 bytes, q = 8 bytes (so n = 7)

  input_block[ 0 ] |= addldata_len ? 0x40 : 0x00;
  process_len = input_len - ( decrypt ? MAC_LENGTH : 0 );
  header_length_declaration = htonl( input_len );
  memcpy( ( void * ) ( input_block + ( AES_BLOCK_SIZE - sizeof( int ) ) ),
    &header_length_declaration, sizeof( unsigned int ) );
  memcpy( ( void * ) ( input_block + 1 ), iv, 8 );
  
  // update the CBC-MAC
  memset( mac_block, '\0', AES_BLOCK_SIZE );
  mxor( input_block, mac_block, AES_BLOCK_SIZE );
  aes_block_encrypt( input_block, mac_block, key, 16 );

  if ( addldata_len )
  {
    int addldata_len_declare;
    int addldata_block_len;
    // First two bytes of addl data are the length in network order
    addldata_len_declare = ntohs( addldata_len );
    memset( input_block, '\0', AES_BLOCK_SIZE );
    memcpy( input_block, ( void * ) &addldata_len_declare,
      sizeof( unsigned short ) );
    addldata_block_len = AES_BLOCK_SIZE - sizeof( unsigned short );

    do
    {
      block_size = ( addldata_len < addldata_block_len ) ?
        addldata_len : addldata_block_len;

      memcpy( input_block + ( AES_BLOCK_SIZE - addldata_block_len ),
        addldata, block_size );
        
      mxor( input_block, mac_block, AES_BLOCK_SIZE );
      aes_block_encrypt( input_block, mac_block, key, 16 );

      addldata_len -= block_size;
      addldata += block_size;
      addldata_block_len = AES_BLOCK_SIZE;
      memset( input_block, '\0', addldata_block_len );
    }
    while ( addldata_len );
  } 

  // Prepare the first nonce
  memset( nonce, '\0', AES_BLOCK_SIZE );
  nonce[ 0 ] = 0x07; // q hardcode to 8 bytes, so n = 7
  memcpy( ( nonce + 1 ), iv, 8 );
  
  while ( process_len )
  {
    // Increment counter
    memcpy( ( void * ) &next_nonce, ( void * ) ( nonce + 12 ), 
      sizeof( unsigned int ) );
    // Preserve byte ordering, although not strictly necessary
    next_nonce = ntohl( next_nonce );
    next_nonce++;
    next_nonce = htonl( next_nonce );
    memcpy( ( void * ) ( nonce + 12 ), ( void * ) &next_nonce, 
      sizeof( unsigned int ) );

    // encrypt the nonce
    block_size = ( process_len < AES_BLOCK_SIZE ) ? process_len : AES_BLOCK_SIZE;
    aes_block_encrypt( nonce, input_block, key, 16 );
    mxor( input_block, input, block_size );  // implement CTR
    memcpy( output, input_block, block_size );
    
    // update the CBC-MAC
    memset( input_block, '\0', AES_BLOCK_SIZE );
    memcpy( input_block, decrypt ? output : input, block_size ); 
    mxor( input_block, mac_block, AES_BLOCK_SIZE );
    aes_block_encrypt( input_block, mac_block, key, 16 );
    
    // advance to next block
    input += block_size;
    output += block_size;
    process_len -= block_size;
  } 

  // Regenerate the first nonce
  memset( nonce, '\0', AES_BLOCK_SIZE );
  nonce[ 0 ] = 0x07; // q hardcode to 8 bytes
  memcpy( ( nonce + 1 ), iv, 8 );
  
  // encrypt the header and output it
  aes_block_encrypt( nonce, input_block, key, AES_BLOCK_SIZE );
  
  // MAC is the CBC-mac mxor'ed with S0
  if ( !decrypt )
  {
    mxor( mac_block, input_block, MAC_LENGTH );
    memcpy( output, mac_block, MAC_LENGTH );
    return 1;
  } 
  else
  {
    mxor( input_block, input, MAC_LENGTH );
    if ( memcmp( mac_block, input_block, MAC_LENGTH ) )
    {
      return 0;
    }
    return 1;
  }
}

int ImAES::aes_gcm_process(cuc *input, int input_len, cuc *addl_data, unsigned short addldata_len, uc *output, void *iv, cuc *key, int decrypt){
  unsigned char nonce[ AES_BLOCK_SIZE ];
  unsigned char input_block[ AES_BLOCK_SIZE ];
  unsigned char zeros[ AES_BLOCK_SIZE ];
  unsigned char H[ AES_BLOCK_SIZE ];
  unsigned char mac_block[ AES_BLOCK_SIZE ];
  unsigned int next_nonce;
  int original_input_len, original_addl_len;
  int process_len;
  int block_size;

  memset( zeros, '\0', AES_BLOCK_SIZE );
  aes_block_encrypt( zeros, H, key, 16 );
  memcpy( nonce, iv, 12 );
  memset( nonce + 12, '\0', sizeof( unsigned int ) );

  process_len = input_len - ( decrypt ? AES_BLOCK_SIZE : 0 );
  
  // MAC initialization
  memset( mac_block, '\0', AES_BLOCK_SIZE );
  original_input_len = htonl( process_len << 3 ); // remember this for final block
  original_addl_len = htonl( addldata_len << 3 ); // remember this for final block

  while ( addldata_len )
  {
    block_size = ( addldata_len < AES_BLOCK_SIZE ) ?
      addldata_len : AES_BLOCK_SIZE;
    memset( input_block, '\0', AES_BLOCK_SIZE );
    memcpy( input_block, addl_data, block_size );
    mxor( input_block, mac_block, AES_BLOCK_SIZE );
    gf_multiply( input_block, H, mac_block );

    addl_data += block_size;
    addldata_len -= block_size;
  }

  next_nonce = htonl( 1 );
  
  while ( process_len )
  {
    next_nonce = ntohl( next_nonce );
    next_nonce++;
    next_nonce = htonl( next_nonce );
    memcpy( ( void * ) ( nonce + 12 ), ( void * ) &next_nonce, 
      sizeof( unsigned int ) );

    block_size = ( process_len < AES_BLOCK_SIZE ) ? process_len : AES_BLOCK_SIZE;
    aes_block_encrypt( nonce, input_block, key, 16 );
    mxor( input_block, input, block_size );  // implement CTR
    memcpy( ( void * ) output, ( void * ) input_block, block_size );

    if ( decrypt )
    {
      // When decrypting, put the input � e.g. the ciphertext -
      // back into the input block for the MAC computation below
      memcpy( input_block, input, block_size );
    }

    // Update the MAC; input_block contains encrypted value
    memset( ( input_block + AES_BLOCK_SIZE ) -
      ( AES_BLOCK_SIZE - block_size ), '\0',
      AES_BLOCK_SIZE - block_size );
    mxor( input_block, mac_block, AES_BLOCK_SIZE );
    gf_multiply( input_block, H, mac_block );

    input += block_size;
    output += block_size;
    process_len -= block_size;
  }
  memset( input_block, '\0', AES_BLOCK_SIZE );
  memcpy( input_block + 4, ( void * ) &original_addl_len,
    sizeof( unsigned int ) ); 
  memcpy( input_block + 12, ( void * ) &original_input_len,
    sizeof( unsigned int ) ); 
  mxor( input_block, mac_block, AES_BLOCK_SIZE );

  // Now encrypt the MAC block and output it
  memset( nonce + 12, '\0', sizeof( unsigned int ) );
  nonce[ 15 ] = 0x01;

  if ( !decrypt )
  {
    gf_multiply( input_block, H, output ); 
    aes_block_encrypt( nonce, input_block, key, 16 );
    mxor( output, input_block, AES_BLOCK_SIZE );
  } 
  else
  {
    gf_multiply( input_block, H, mac_block );

    // Now decrypt the final (MAC) block and compare it
    aes_block_encrypt( nonce, input_block, key, 16 );
    mxor( input_block, input, AES_BLOCK_SIZE );

    if ( memcmp( mac_block, input_block, AES_BLOCK_SIZE ) )
    {
      return 1;
    }
  }
  
  return 0;
}

sv ImAES::aes_encrypt(cuc *input, int input_len, uc *output, cuc *iv, cuc *key, int key_length){
  unsigned char input_block[ AES_BLOCK_SIZE ];
  
  while ( input_len >= AES_BLOCK_SIZE )
  { 
    memcpy( input_block, input, AES_BLOCK_SIZE );
    mxor( input_block, iv, AES_BLOCK_SIZE ); // implement CBC
    aes_block_encrypt( input_block, output, key, key_length );
    memcpy( ( void * ) iv, ( void * ) output, AES_BLOCK_SIZE ); // CBC
    input += AES_BLOCK_SIZE;
    output += AES_BLOCK_SIZE;
    input_len -= AES_BLOCK_SIZE;
  }
}

sv ImAES::aes_decrypt(cuc *input, int input_len, uc *output, cuc *iv, cuc *key, int key_length){
  while ( input_len >= AES_BLOCK_SIZE )
  {
    aes_block_decrypt( input, output, key, key_length );
    mxor( output, iv, AES_BLOCK_SIZE );
    memcpy( ( void * ) iv, ( void * ) input, AES_BLOCK_SIZE ); // CBC
    input += AES_BLOCK_SIZE;
    output += AES_BLOCK_SIZE;
    input_len -= AES_BLOCK_SIZE;
  }
}
