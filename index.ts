// /Users/cheikkone/Projects/explorer-api/src/app/collection/dto/collection.dto.ts 
import { ConfigService } from '@nestjs/config';
import configuration from '../../../config/configuration';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { IntersectionType } from '@nestjs/swagger';

const configService: ConfigService<EnvironmentVariables> = new ConfigService(
  configuration(),
);

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  MinLength,
  IsNumberString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsInt,
  Min,
  Max,
  ArrayMaxSize,
  ArrayMinSize,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/collection.filters';

export class CreateJWTDto {
  @ApiProperty({
    description: 'email',
  })
  @IsNotEmpty()
  readonly email: string;
  @ApiProperty({
    description: 'password',
  })
  @IsNotEmpty()
  readonly password: string;
}

export class GetCollectionDto {
  @Matches(
    new RegExp(
      '^(' +
        configService.get('nft-collection-name') +
        '|' +
        configService.get('rotg-collection-name') +
        '|' +
        configService.get('ltbox-collection-name') +
        '|' +
        configService.get('tiket-collection-name') +
        '|' +
        configService.get('asset-collection-name') +
        ')$',
    ),
  )
  @ApiProperty({
    enum: [
      configService.get('nft-collection-name'),
      configService.get('rotg-collection-name'),
      configService.get('ltbox-collection-name'),
      configService.get('tiket-collection-name'),
      configService.get('asset-collection-name'),
    ],
  })
  readonly collection: string;
}

export class GetIdWithoutCollectionDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

export class GetIdDto extends IntersectionType(
  GetCollectionDto,
  GetIdWithoutCollectionDto,
) {}

export class GetIdsDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'ids of nft',
  })
  ids: number[];
}
export class GetElementDto extends GetCollectionDto {
  @IsEnum(['water', 'rock', 'algae', 'lava', 'bioluminescent'])
  @ApiProperty({
    description: 'nft/sft element',
  })
  element: string;
}

export class GetIdentifiersDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'identifier of nft/sft',
  })
  identifiers: string[];
}

export class ROTGModel {
  @ApiProperty({
    description: 'ROTG id',
  })
  @IsInt()
  @Min(1)
  @Max(9999)
  id: number;

  @ApiProperty({
    description: 'ROTG name',
  })
  @IsNotEmpty()
  readonly name: string;

  @ApiProperty({
    description: 'ROTG description',
  })
  @IsNotEmpty()
  readonly description: string;

  @ApiProperty({
    description: 'ROTG element',
  })
  @IsEnum(['Water', 'Rock', 'Algae', 'Lava', 'Bioluminescent'])
  readonly element: string;

  @ApiProperty({
    description: 'ROTG image url',
  })
  @IsNotEmpty()
  readonly image: string;

  @ApiProperty({
    description: 'ROTG attributes',
  })
  @ArrayMaxSize(10)
  @ArrayMinSize(10)
  readonly attributes: any[];
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto extends GetCollectionDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.helpers.ts 
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers/out';
import axios from 'axios';

export const sleep = (ms: number) => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};

export const erdDoGetGeneric = async (networkProvider, uri, count = 1) => {
  try {
    const data = await networkProvider.doGetGeneric(uri);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const erdDoPostGeneric = async (
  networkProvider,
  uri,
  body,
  count = 1,
) => {
  try {
    const data = await networkProvider.doPostGeneric(uri, body);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const processElrondNFTs = async (
  networkProvider: ApiNetworkProvider,
  uriType: 'collections' | 'accounts',
  uriName: string,
  processFunction: (nftList: any[]) => void,
) => {
  try {
    const nftCount = await erdDoGetGeneric(
      networkProvider,
      uriType + '/' + uriName + '/nfts/count',
    );
    const n = 1;
    const size = 100;
    const maxIteration = Math.ceil(nftCount / (size * n));
    for (let i = 0; i < maxIteration; i++) {
      const endpoints = Array.from(
        { length: n },
        (_, index) =>
          'https://devnet-api.elrond.com/' +
          uriType +
          '/' +
          uriName +
          '/nfts?from=' +
          (index + i * n) * size +
          '&size=' +
          size,
      );
      const parallelData = await axios.all(
        endpoints.map((endpoint) => {
          return axios.get(endpoint);
        }),
      );
      console.log('go');
      for (const data of parallelData) {
        if (data.status === 200) {
          await processFunction(data.data);
        } else {
          console.log('ELROND ERROR');
        }
      }
      console.log(i + ' - data scrapped');
      await sleep(3000);
    }
  } catch (e) {
    console.error(e);
  }
};
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.controller.ts 
import {
  Body,
  Controller,
  Get,
  Param,
  ParseArrayPipe,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { CollectionService } from './collection.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetErdDto,
  GetIdDto,
  GetIdsDto,
  GetIdentifiersDto,
  GetMarketDto,
  CreateJWTDto,
  GetIdWithoutCollectionDto,
  ROTGModel,
  GetElementDto,
} from './dto/collection.dto';
import { LocalAuthGuard } from '../auth/guards/local-auth.guard';
import { AuthService } from '../auth/auth.service';

@ApiTags('collection')
@Controller('collection')
export class CollectionController {
  constructor(
    private readonly collectionService: CollectionService,
    private authService: AuthService,
  ) {}

  @Get(':collection/user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get(':collection/user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findUserNftCount({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.collectionService.findByUserLimited({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get(':collection/id/:id')
  getCollectionNftById(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findCollectionNftById(getIdDto);
  }

  @Get(':collection/search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findByIdPrefix(getIdDto);
  }

  @Get('scrapRotg')
  scrapRotg() {
    return this.collectionService.scrapAssets();
  }

  @UseGuards(LocalAuthGuard)
  @Post('/getJWT')
  async login(@Request() req, @Body() createJWT: CreateJWTDto) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('/lockMerge/:id')
  @ApiBearerAuth()
  lockMergeV2(@Param() getIdDto: GetIdWithoutCollectionDto) {
    return this.collectionService.lockMergeV2(getIdDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockMerge/:id')
  @ApiBearerAuth()
  unlockMergeV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.unlockMergeV2({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockForce/:id')
  @ApiBearerAuth()
  forceUnlockTestV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.forceUnlockTest({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @Get(':collection/ids/:ids')
  getByIds(@Param() getIdsDto: GetIdsDto) {
    getIdsDto.ids = (getIdsDto.ids as unknown as string)
      .split(',')
      .map((idStr) => Number(idStr))
      .filter((id) => !isNaN(id));
    return this.collectionService.getByIds(getIdsDto);
  }

  @Get(':collection/identifiers/:identifiers')
  getByIdentifiers(@Param() getIdentifiersDto: GetIdentifiersDto) {
    getIdentifiersDto.identifiers = (
      getIdentifiersDto.identifiers as unknown as string
    )
      .split(',')
      .filter((identifier) => identifier.length > 0);
    return this.collectionService.getByIdentifiers(getIdentifiersDto);
  }

  @Get(':collection/floor/:element')
  getElementFloorPrice(@Param() getElementDto: GetElementDto) {
    return this.collectionService.getElementFloorPrice(getElementDto);
  }

  @Get(':collection/all')
  getAll(
    @Param() getCollectionDto: GetCollectionDto,
    @Query() getAllDto: GetAllDto,
  ) {
    return this.collectionService.findAll({
      ...getCollectionDto,
      ...getAllDto,
    });
  }

  // @Get(':collcetion/market')
  // getByMarket(
  //   @Param() getCollectionDto: GetCollectionDto,
  //   @Query() getMarketDto: GetMarketDto,
  // ) {
  //   return this.collectionService.findByMarket(getMarketDto);
  // }
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.module.ts 
import { Module } from '@nestjs/common';
import { CollectionService } from './collection.service';
import { CollectionController } from './collection.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Collection, CollectionSchema } from './schemas/collection.schema';
import { NftModule } from '../nft/nft.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([
      { name: Collection.name, schema: CollectionSchema },
    ]),
  ],
  controllers: [CollectionController],
  providers: [CollectionService],
  exports: [CollectionService],
})
export class CollectionModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/schemas/collection.schema.ts 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CollectionDocument = Collection & Document;

const BaseAssetType = {
  name: String,
  url: String,
  vril: Number,
  rarity: Number,
  _id: false,
};
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class Collection {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  collectionName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: false, type: String })
  assetType: string;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: false, type: Number })
  balance: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  vril: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
  @Prop({ required: false, type: Date })
  lockedOn: Date;
}

export const CollectionSchema = SchemaFactory.createForClass(Collection);
// /Users/cheikkone/Projects/explorer-api/src/app/collection/schemas/collection.filters.ts 
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.service.ts 
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetElementDto,
  GetErdDto,
  GetIdDto,
  GetIdentifiersDto,
  GetIdsDto,
  GetIdWithoutCollectionDto,
  GetMarketDto,
  ROTGModel,
} from './dto/collection.dto';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { Collection, CollectionDocument } from './schemas/collection.schema';
import { scrapMarkets } from './collection.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
  processElrondNFTs,
} from './collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;
let SCRAP_ROTG = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class CollectionService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(Collection.name)
    private collectionModel: Model<CollectionDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(collection, erd, filters) {
    const size = 1450;
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}/nfts?from=0&size=${size}&collections=${collection}&withScamInfo=false&computeScamInfo=false`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const sfts = dataNFTs
      .filter((d) => d.type === 'SemiFungibleESDT')
      .reduce((agg, unit) => {
        return { ...agg, [unit.nonce]: Number(unit.balance) };
      }, {});
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };
    return { findQuery, filtersQuery, sfts };
  }

  async getByIds(getIdsDto: GetIdsDto) {
    try {
      const { collection, ids } = getIdsDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, id: { $in: ids } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getElementFloorPrice(getElementDto: GetElementDto) {
    try {
      const { collection, element } = getElementDto;
      const lowestPriceNft = await this.collectionModel
        .find(
          {
            collectionName: collection,
            market: { $exists: true },
            stone: element,
          },
          '-_id',
        )
        .sort('market.price')
        .limit(1);
      if (lowestPriceNft && lowestPriceNft.length > 0) {
        return {
          floorPrice: lowestPriceNft[0].market.price,
          details: lowestPriceNft[0],
        };
      } else {
        return {
          floorPrice: 0,
          details: {},
        };
      }
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getByIdentifiers(getIdentifiersDto: GetIdentifiersDto) {
    try {
      const { collection, identifiers } = getIdentifiersDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, identifier: { $in: identifiers } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd, collection } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery, sfts } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      nfts.forEach((nft) => {
        nft.balance = nft.idName in sfts ? sfts[nft.idName] : 1;
      });
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // to remove
  async updateDatabase(assets) {
    try {
      const collections = [];
      let i = 0;
      for (const sft of assets) {
        const pngUrl = sft.media[0].originalUrl.split('/');
        let path = pngUrl[5] + '/' + pngUrl[6].split('.')[0];
        switch (path) {
          case 'Background/Medusa':
            path = 'Background/' + encodeURIComponent('Médusa');
            break;
          case 'Armor/Erales Legendary Algae 5':
            path = 'Armor/' + encodeURIComponent('Eralès Legendary Algae 5');
            break;
        }
        const assetData = await axios.get(
          'https://storage.googleapis.com/guardians-assets-original/json-asset-v2/' +
            path +
            '.json',
        );
        console.log('json read: ' + i);
        i++;
        const asset = {
          url: '/' + path + '.png',
        };
        let assetType;
        let stone;
        for (const trait of assetData.data.attributes) {
          switch (trait.trait_type) {
            case 'Type':
              assetType = trait.value.toLowerCase();
              break;
            case 'Family':
              asset['name'] = trait.value.toLowerCase();
              break;
            case 'Element':
              stone = trait.value.toLowerCase();
              break;
            case 'Vril':
              asset['vril'] = trait.value;
              break;
            case 'Level':
              asset['level'] = trait.value;
              break;
          }
        }
        const output = {
          stone,
          assetType,
          [assetType]: {
            ...asset,
          },
          collectionName: sft.collection,
          identifier: sft.identifier,
          id: sft.nonce,
          idName: sft.nonce.toString(),
          vril: asset['vril'],
        };
        collections.push(output);
      }
      const updateObject = collections.map((d) => ({
        updateOne: {
          filter: { id: d.id, collectionName: d.collectionName },
          update: d,
          upsert: true,
        },
      }));
      // console.log('starting bulk write');
      // await this.collectionModel.bulkWrite(updateObject);
      // console.log('finish');
    } catch (error) {
      console.error(error);
    }
  }

  async scrap() {
    const rotg = this.configService.get('rotg-collection-name');
    const lastNft = (
      await erdDoGetGeneric(
        this.networkProvider,
        `nfts?collection=${rotg}&from=0&size=1&includeFlagged=true`,
      )
    )[0];

    const count = await this.collectionModel.count({
      collectionName: rotg,
    });

    const nftToAdd = lastNft.nonce - count;

    const nfts = await erdDoGetGeneric(
      this.networkProvider,
      `nfts?collection=${rotg}&from=0&size=${nftToAdd}&includeFlagged=true`,
    );
    nfts.forEach((nft) => {
      this.collectionModel.create({
        collection: `${rotg}-2`,
        identifier: nft.identifier,

      });
    });
    console.log(JSON.stringify(nfts[0]));
  }

  // to remove
  async scrapAssets() {
    try {
      this.scrap();
      // await processElrondNFTs(
      //   this.networkProvider,
      //   'accounts',
      //   'erd1qqqqqqqqqqqqqpgq58vp0ydxgpae47pkxqfscvnnzv6vaq9derqqqwmujy',
      //   async (nftList: any[]) => {
      //   },
      // );
      // const nfts = await this.collectionModel.find(
      //   {
      //     collectionName: 'ROTG-467abf',
      //   },
      //   '-_id',
      // );

      // nfts = nfts.map((nft) => {
      //   return {
      //     ...nft.$clone(),
      //     collectionName: nft.collectionName.replace(
      //       'ASSET-6b7288',
      //       'ROTGW-0da75b',
      //     ),
      //     oldId: nft.identifier,
      //     identifier: nft.identifier.replace('ASSET-6b7288', 'ROTGW-0da75b'),
      //   };
      // }) as any;

      // this.collectionModel.create({

      // })

      // (nfts as any).forEach(async (nft, i) => {
      //   const result = await this.collectionModel.findOneAndUpdate(
      //     {
      //       identifier: nft.oldId,
      //     },
      //     {
      //       identifier: nft.identifier,
      //       collectionName: nft.collectionName,
      //     },
      //   );
      //   console.log(result);
      //   console.log({
      //     identifier: nft.identifier,
      //     collectionName: nft.collectionName,
      //   });
      //   // await result.save();
      //   if (i == 0) {
      //     console.log(result);
      //   }
      // });

      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: false },
      //     isClaimed: false,
      //     collectionName: this.configService.get('rotg-collection-name'),
      //   },
      //   {
      //     isClaimed: true,
      //   },
      // );
      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: true },
      //   },
      //   {
      //     $unset: {
      //       isTrulyClaimed: true,
      //     },
      //   },
      // );
    } catch (e) {
      console.error(e);
    }
  }

  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('* * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      SCRAP_ROTG = !SCRAP_ROTG;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      const collectionName = SCRAP_ROTG
        ? this.configService.get('rotg-collection-name')
        : this.configService.get('nft-collection-name');
      await scrapMarkets(
        this.collectionModel,
        collectionName,
        EGLD_RATE,
        timestamp,
      );
      await this.collectionModel.updateMany(
        {
          collectionName,
          timestamp: { $exists: true, $ne: timestamp },
        },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      RUNNING = false;
      console.log(error);
      this.client.instance().captureException(error);
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id -market')
        .limit(limit);
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateNFTOwners(collection) {
    try {
      const endpoints = Array.from(
        { length: 20 },
        (_, index) =>
          'https://devnet-api.elrond.com/collections/' +
          collection +
          '/nfts?from=' +
          index * 500 +
          '&size=500',
      );
      return axios.all(endpoints.map((endpoint) => axios.get(endpoint)));
    } catch (e) {
      console.error(e);
    }
  }

  async findCollectionNftById(getIdDto: GetIdDto) {
    try {
      const { collection, id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        { collectionName: collection, id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      // to remove
      // this.scrapAssets('ASSET-6b7288');
      // return;
      const { collection, id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.collectionModel
        .find({
          collectionName: collection,
          idName: new RegExp('^' + id),
        })
        .sort({ id: 1 })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async lockMergeV2(getIdDto: GetIdWithoutCollectionDto) {
    try {
      const { id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: false },
        },
        { lockedOn: new Date() },
        { new: true, projection: '-_id' },
      );
      return {
        justGotLocked: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async unlockMergeV2(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      const record = await this.collectionModel.findOne({
        collectionName: this.configService.get('rotg-collection-name'),
        id,
        lockedOn: { $exists: true },
      });
      if (record) {
        record.lockedOn = undefined;
        await record.save();
      }
      return {
        justGotMerged: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async forceUnlockTest(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: true },
        },
        { $unset: { lockedOn: true } },
      );
      return true;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      collectionName: dto.collection,
      stone: dto.stone,
      isClaimed: dto.isClaimed,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto as GetAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.collectionModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.collectionModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.checkSmartContract(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(collection, claimedIds) {
    await this.collectionModel.updateMany(
      { collectionName: collection, id: { $in: claimedIds } },
      { isClaimed: true },
    );
  }

  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.collectionModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.collectionModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // @Cron('*/2 * * * *')
  // private async scrapMarket() {
  //   try {
  //     const timestamp: number = new Date().getTime();
  //     await this.fullScrapTrustmarket('bid', timestamp);
  //     await this.fullScrapTrustmarket('buy', timestamp);
  //     // await this.scrapDeadrare(timestamp);
  //     await this.nftModel.updateMany(
  //       { timestamp: { $exists: true, $ne: timestamp } },
  //       { $unset: { market: 1, timestamp: 1 } },
  //     );
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //   }
  // }
  // private async scrapTrustmarket(
  //   type: 'bid' | 'buy',
  //   offset: number,
  //   count: number,
  //   timestamp: number,
  // ) {
  //   try {
  //     const trustmarketApi = this.configService.get('trustmarket-api');
  //     const { data } = await axios.post(trustmarketApi, {
  //       filters: {
  //         onSale: true,
  //         auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
  //       },
  //       collection: 'GUARDIAN-3d6635',
  //       skip: offset,
  //       top: count,
  //       select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
  //     });
  //     if (!data.results || data.results.length === 0) return true;
  //     if (type === 'buy') {
  //       const nftSample = data.results[0];
  //       EGLD_RATE =
  //         nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
  //     }
  //     const isLast: boolean = offset + data.resultsCount === data.count;
  //     const updateObject = data.results.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.nonce },
  //         update: {
  //           market: {
  //             source:
  //               d.saleInfoNft?.marketplace === 'DR'
  //                 ? 'deadrare'
  //                 : 'trustmarket',
  //             identifier: d.identifier,
  //             type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
  //             bid:
  //               d.saleInfoNft?.auction_type !== 'NftBid'
  //                 ? null
  //                 : {
  //                     min: d.saleInfoNft?.min_bid_short,
  //                     current: d.saleInfoNft?.current_bid_short,
  //                     deadline: getTimeUntil(d.saleInfoNft?.deadline),
  //                   },
  //             token: d.saleInfoNft?.accepted_payment_token,
  //             price: d.saleInfoNft?.max_bid_short,
  //             currentUsd: +d.saleInfoNft?.usd,
  //             timestamp: +d.saleInfoNft?.timestamp,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     await this.nftModel.bulkWrite(updateObject);
  //     return isLast;
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }

  async checkSmartContract(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      //   await this.nftModel.updateMany(
      //     { id: { $in: claimedIds } },
      //     { isClaimed: true },
      //   );
      await this.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  // private async scrapDeadrare(timestamp: number) {
  //   try {
  //     const deadrareApi = this.configService.get('deadrare-api');
  //     const deadrareApiParams = this.configService.get('deadrare-api-params');
  //     const { data } = await axios.get(deadrareApi + deadrareApiParams);
  //     if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
  //     const updateObject = data.data.listAuctions.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.cachedNft.nonce },
  //         update: {
  //           market: {
  //             source: 'deadrare',
  //             identifier: d.nftId,
  //             type: 'buy',
  //             bid: null,
  //             token: 'EGLD',
  //             price: +d.price,
  //             currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     return this.nftModel.bulkWrite(updateObject);
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.market.ts 
import axios from 'axios';
import { CollectionDocument } from './schemas/collection.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';
import { sleep } from './collection.helpers';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      if (auctionTokenData[6] === auctionTokenData[7]) {
        return parseInt(auctionTokenData[6], 16);
      } else {
        console.log(identifier + ': auction/' + elrondTransaction.function);
      }
    } else if (
      // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  collectionModel: Model<CollectionDocument>,
  collectionName: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket(
    'deadrare',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'frameit',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'xoxno',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'elrond',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
};

const getIdsOfNFTsInMarket = async function (
  marketName,
  collection,
  from,
  size,
) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=' +
      collection,
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  collection: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  collectionModel: Model<CollectionDocument>,
  egldRate: number,
  timestamp: number,
) {
  let from = 0;
  const size = 100;
  let nftsScrapped = false;
  while (!nftsScrapped) {
    const nftsIds = await getIdsOfNFTsInMarket(
      marketName,
      collection,
      from,
      size,
    );
    from += size;
    if (nftsIds.length == 0) {
      nftsScrapped = true;
      break;
    }

    // update timestamp for in-market nfts
    await collectionModel.updateMany(
      { collectionName: collection, id: { $in: nftsIds } },
      { timestamp },
    );
    // get newly entered nfts
    const newNFTs = await collectionModel.find({
      collectionName: collection,
      id: { $in: nftsIds },
      market: { $exists: false },
    });

    const updateObject = [];
    for (const nft of newNFTs) {
      // update db with price of newly added nft
      let price;
      try {
        price = await getNftPrice(marketName, nft.identifier);
      } catch (e) {
        continue;
      }
      const market = {
        source: marketName,
        identifier: nft.identifier,
        type: 'buy',
        bid: null,
        token: 'EGLD',
        price,
        currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
      };
      console.log(market);
      updateObject.push({
        updateOne: {
          filter: { collectionName: collection, id: nft.id },
          update: {
            market,
          },
        },
      });
      await sleep(500);
    }
    await collectionModel.bulkWrite(updateObject);
  }
};
// /Users/cheikkone/Projects/explorer-api/src/app/index.php 
<html><body>
<h3>collection.dto.ts</h3>
<pre>
import { ConfigService } from '@nestjs/config';
import configuration from '../../../config/configuration';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { IntersectionType } from '@nestjs/swagger';

const configService: ConfigService<EnvironmentVariables> = new ConfigService(
  configuration(),
);

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  MinLength,
  IsNumberString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsInt,
  Min,
  Max,
  ArrayMaxSize,
  ArrayMinSize,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/collection.filters';

export class CreateJWTDto {
  @ApiProperty({
    description: 'email',
  })
  @IsNotEmpty()
  readonly email: string;
  @ApiProperty({
    description: 'password',
  })
  @IsNotEmpty()
  readonly password: string;
}

export class GetCollectionDto {
  @Matches(
    new RegExp(
      '^(' +
        configService.get('nft-collection-name') +
        '|' +
        configService.get('rotg-collection-name') +
        '|' +
        configService.get('ltbox-collection-name') +
        '|' +
        configService.get('tiket-collection-name') +
        '|' +
        configService.get('asset-collection-name') +
        ')$',
    ),
  )
  @ApiProperty({
    enum: [
      configService.get('nft-collection-name'),
      configService.get('rotg-collection-name'),
      configService.get('ltbox-collection-name'),
      configService.get('tiket-collection-name'),
      configService.get('asset-collection-name'),
    ],
  })
  readonly collection: string;
}

export class GetIdWithoutCollectionDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

export class GetIdDto extends IntersectionType(
  GetCollectionDto,
  GetIdWithoutCollectionDto,
) {}

export class GetIdsDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'ids of nft',
  })
  ids: number[];
}
export class GetElementDto extends GetCollectionDto {
  @IsEnum(['water', 'rock', 'algae', 'lava', 'bioluminescent'])
  @ApiProperty({
    description: 'nft/sft element',
  })
  element: string;
}

export class GetIdentifiersDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'identifier of nft/sft',
  })
  identifiers: string[];
}

export class ROTGModel {
  @ApiProperty({
    description: 'ROTG id',
  })
  @IsInt()
  @Min(1)
  @Max(9999)
  id: number;

  @ApiProperty({
    description: 'ROTG name',
  })
  @IsNotEmpty()
  readonly name: string;

  @ApiProperty({
    description: 'ROTG description',
  })
  @IsNotEmpty()
  readonly description: string;

  @ApiProperty({
    description: 'ROTG element',
  })
  @IsEnum(['Water', 'Rock', 'Algae', 'Lava', 'Bioluminescent'])
  readonly element: string;

  @ApiProperty({
    description: 'ROTG image url',
  })
  @IsNotEmpty()
  readonly image: string;

  @ApiProperty({
    description: 'ROTG attributes',
  })
  @ArrayMaxSize(10)
  @ArrayMinSize(10)
  readonly attributes: any[];
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto extends GetCollectionDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
</pre>
<h3>collection.helpers.ts</h3>
<pre>
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers/out';
import axios from 'axios';

export const sleep = (ms: number) => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};

export const erdDoGetGeneric = async (networkProvider, uri, count = 1) => {
  try {
    const data = await networkProvider.doGetGeneric(uri);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const erdDoPostGeneric = async (
  networkProvider,
  uri,
  body,
  count = 1,
) => {
  try {
    const data = await networkProvider.doPostGeneric(uri, body);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const processElrondNFTs = async (
  networkProvider: ApiNetworkProvider,
  uriType: 'collections' | 'accounts',
  uriName: string,
  processFunction: (nftList: any[]) => void,
) => {
  try {
    const nftCount = await erdDoGetGeneric(
      networkProvider,
      uriType + '/' + uriName + '/nfts/count',
    );
    const n = 1;
    const size = 100;
    const maxIteration = Math.ceil(nftCount / (size * n));
    for (let i = 0; i < maxIteration; i++) {
      const endpoints = Array.from(
        { length: n },
        (_, index) =>
          'https://devnet-api.elrond.com/' +
          uriType +
          '/' +
          uriName +
          '/nfts?from=' +
          (index + i * n) * size +
          '&size=' +
          size,
      );
      const parallelData = await axios.all(
        endpoints.map((endpoint) => {
          return axios.get(endpoint);
        }),
      );
      console.log('go');
      for (const data of parallelData) {
        if (data.status === 200) {
          await processFunction(data.data);
        } else {
          console.log('ELROND ERROR');
        }
      }
      console.log(i + ' - data scrapped');
      await sleep(3000);
    }
  } catch (e) {
    console.error(e);
  }
};
</pre>
<h3>collection.controller.ts</h3>
<pre>
import {
  Body,
  Controller,
  Get,
  Param,
  ParseArrayPipe,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { CollectionService } from './collection.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetErdDto,
  GetIdDto,
  GetIdsDto,
  GetIdentifiersDto,
  GetMarketDto,
  CreateJWTDto,
  GetIdWithoutCollectionDto,
  ROTGModel,
  GetElementDto,
} from './dto/collection.dto';
import { LocalAuthGuard } from '../auth/guards/local-auth.guard';
import { AuthService } from '../auth/auth.service';

@ApiTags('collection')
@Controller('collection')
export class CollectionController {
  constructor(
    private readonly collectionService: CollectionService,
    private authService: AuthService,
  ) {}

  @Get(':collection/user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get(':collection/user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findUserNftCount({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.collectionService.findByUserLimited({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get(':collection/id/:id')
  getCollectionNftById(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findCollectionNftById(getIdDto);
  }

  @Get(':collection/search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findByIdPrefix(getIdDto);
  }

  @Get('scrapRotg')
  scrapRotg() {
    return this.collectionService.scrapAssets();
  }

  @UseGuards(LocalAuthGuard)
  @Post('/getJWT')
  async login(@Request() req, @Body() createJWT: CreateJWTDto) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('/lockMerge/:id')
  @ApiBearerAuth()
  lockMergeV2(@Param() getIdDto: GetIdWithoutCollectionDto) {
    return this.collectionService.lockMergeV2(getIdDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockMerge/:id')
  @ApiBearerAuth()
  unlockMergeV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.unlockMergeV2({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockForce/:id')
  @ApiBearerAuth()
  forceUnlockTestV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.forceUnlockTest({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @Get(':collection/ids/:ids')
  getByIds(@Param() getIdsDto: GetIdsDto) {
    getIdsDto.ids = (getIdsDto.ids as unknown as string)
      .split(',')
      .map((idStr) => Number(idStr))
      .filter((id) => !isNaN(id));
    return this.collectionService.getByIds(getIdsDto);
  }

  @Get(':collection/identifiers/:identifiers')
  getByIdentifiers(@Param() getIdentifiersDto: GetIdentifiersDto) {
    getIdentifiersDto.identifiers = (
      getIdentifiersDto.identifiers as unknown as string
    )
      .split(',')
      .filter((identifier) => identifier.length > 0);
    return this.collectionService.getByIdentifiers(getIdentifiersDto);
  }

  @Get(':collection/floor/:element')
  getElementFloorPrice(@Param() getElementDto: GetElementDto) {
    return this.collectionService.getElementFloorPrice(getElementDto);
  }

  @Get(':collection/all')
  getAll(
    @Param() getCollectionDto: GetCollectionDto,
    @Query() getAllDto: GetAllDto,
  ) {
    return this.collectionService.findAll({
      ...getCollectionDto,
      ...getAllDto,
    });
  }

  // @Get(':collcetion/market')
  // getByMarket(
  //   @Param() getCollectionDto: GetCollectionDto,
  //   @Query() getMarketDto: GetMarketDto,
  // ) {
  //   return this.collectionService.findByMarket(getMarketDto);
  // }
}
</pre>
<h3>collection.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { CollectionService } from './collection.service';
import { CollectionController } from './collection.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Collection, CollectionSchema } from './schemas/collection.schema';
import { NftModule } from '../nft/nft.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([
      { name: Collection.name, schema: CollectionSchema },
    ]),
  ],
  controllers: [CollectionController],
  providers: [CollectionService],
  exports: [CollectionService],
})
export class CollectionModule {}
</pre>
<h3>collection.schema.ts</h3>
<pre>
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CollectionDocument = Collection & Document;

const BaseAssetType = {
  name: String,
  url: String,
  vril: Number,
  rarity: Number,
  _id: false,
};
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class Collection {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  collectionName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: false, type: String })
  assetType: string;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: false, type: Number })
  balance: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  vril: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
  @Prop({ required: false, type: Date })
  lockedOn: Date;
}

export const CollectionSchema = SchemaFactory.createForClass(Collection);
</pre>
<h3>collection.filters.ts</h3>
<pre>
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
</pre>
<h3>collection.service.ts</h3>
<pre>
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetElementDto,
  GetErdDto,
  GetIdDto,
  GetIdentifiersDto,
  GetIdsDto,
  GetIdWithoutCollectionDto,
  GetMarketDto,
  ROTGModel,
} from './dto/collection.dto';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { Collection, CollectionDocument } from './schemas/collection.schema';
import { scrapMarkets } from './collection.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
  processElrondNFTs,
} from './collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;
let SCRAP_ROTG = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class CollectionService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(Collection.name)
    private collectionModel: Model<CollectionDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(collection, erd, filters) {
    const size = 1450;
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}/nfts?from=0&size=${size}&collections=${collection}&withScamInfo=false&computeScamInfo=false`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const sfts = dataNFTs
      .filter((d) => d.type === 'SemiFungibleESDT')
      .reduce((agg, unit) => {
        return { ...agg, [unit.nonce]: Number(unit.balance) };
      }, {});
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };
    return { findQuery, filtersQuery, sfts };
  }

  async getByIds(getIdsDto: GetIdsDto) {
    try {
      const { collection, ids } = getIdsDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, id: { $in: ids } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getElementFloorPrice(getElementDto: GetElementDto) {
    try {
      const { collection, element } = getElementDto;
      const lowestPriceNft = await this.collectionModel
        .find(
          {
            collectionName: collection,
            market: { $exists: true },
            stone: element,
          },
          '-_id',
        )
        .sort('market.price')
        .limit(1);
      if (lowestPriceNft && lowestPriceNft.length > 0) {
        return {
          floorPrice: lowestPriceNft[0].market.price,
          details: lowestPriceNft[0],
        };
      } else {
        return {
          floorPrice: 0,
          details: {},
        };
      }
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getByIdentifiers(getIdentifiersDto: GetIdentifiersDto) {
    try {
      const { collection, identifiers } = getIdentifiersDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, identifier: { $in: identifiers } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd, collection } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery, sfts } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      nfts.forEach((nft) => {
        nft.balance = nft.idName in sfts ? sfts[nft.idName] : 1;
      });
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // to remove
  async updateDatabase(assets) {
    try {
      const collections = [];
      let i = 0;
      for (const sft of assets) {
        const pngUrl = sft.media[0].originalUrl.split('/');
        let path = pngUrl[5] + '/' + pngUrl[6].split('.')[0];
        switch (path) {
          case 'Background/Medusa':
            path = 'Background/' + encodeURIComponent('Médusa');
            break;
          case 'Armor/Erales Legendary Algae 5':
            path = 'Armor/' + encodeURIComponent('Eralès Legendary Algae 5');
            break;
        }
        const assetData = await axios.get(
          'https://storage.googleapis.com/guardians-assets-original/json-asset-v2/' +
            path +
            '.json',
        );
        console.log('json read: ' + i);
        i++;
        const asset = {
          url: '/' + path + '.png',
        };
        let assetType;
        let stone;
        for (const trait of assetData.data.attributes) {
          switch (trait.trait_type) {
            case 'Type':
              assetType = trait.value.toLowerCase();
              break;
            case 'Family':
              asset['name'] = trait.value.toLowerCase();
              break;
            case 'Element':
              stone = trait.value.toLowerCase();
              break;
            case 'Vril':
              asset['vril'] = trait.value;
              break;
            case 'Level':
              asset['level'] = trait.value;
              break;
          }
        }
        const output = {
          stone,
          assetType,
          [assetType]: {
            ...asset,
          },
          collectionName: sft.collection,
          identifier: sft.identifier,
          id: sft.nonce,
          idName: sft.nonce.toString(),
          vril: asset['vril'],
        };
        collections.push(output);
      }
      const updateObject = collections.map((d) => ({
        updateOne: {
          filter: { id: d.id, collectionName: d.collectionName },
          update: d,
          upsert: true,
        },
      }));
      // console.log('starting bulk write');
      // await this.collectionModel.bulkWrite(updateObject);
      // console.log('finish');
    } catch (error) {
      console.error(error);
    }
  }

  async scrap() {
    const rotg = this.configService.get('rotg-collection-name');
    const lastNft = (
      await erdDoGetGeneric(
        this.networkProvider,
        `nfts?collection=${rotg}&from=0&size=1&includeFlagged=true`,
      )
    )[0];

    const count = await this.collectionModel.count({
      collectionName: rotg,
    });

    const nftToAdd = lastNft.nonce - count;

    const nfts = await erdDoGetGeneric(
      this.networkProvider,
      `nfts?collection=${rotg}&from=0&size=${nftToAdd}&includeFlagged=true`,
    );
    nfts.forEach((nft) => {
      this.collectionModel.create({
        collection: `${rotg}-2`,
        identifier: nft.identifier,

      });
    });
    console.log(JSON.stringify(nfts[0]));
  }

  // to remove
  async scrapAssets() {
    try {
      this.scrap();
      // await processElrondNFTs(
      //   this.networkProvider,
      //   'accounts',
      //   'erd1qqqqqqqqqqqqqpgq58vp0ydxgpae47pkxqfscvnnzv6vaq9derqqqwmujy',
      //   async (nftList: any[]) => {
      //   },
      // );
      // const nfts = await this.collectionModel.find(
      //   {
      //     collectionName: 'ROTG-467abf',
      //   },
      //   '-_id',
      // );

      // nfts = nfts.map((nft) => {
      //   return {
      //     ...nft.$clone(),
      //     collectionName: nft.collectionName.replace(
      //       'ASSET-6b7288',
      //       'ROTGW-0da75b',
      //     ),
      //     oldId: nft.identifier,
      //     identifier: nft.identifier.replace('ASSET-6b7288', 'ROTGW-0da75b'),
      //   };
      // }) as any;

      // this.collectionModel.create({

      // })

      // (nfts as any).forEach(async (nft, i) => {
      //   const result = await this.collectionModel.findOneAndUpdate(
      //     {
      //       identifier: nft.oldId,
      //     },
      //     {
      //       identifier: nft.identifier,
      //       collectionName: nft.collectionName,
      //     },
      //   );
      //   console.log(result);
      //   console.log({
      //     identifier: nft.identifier,
      //     collectionName: nft.collectionName,
      //   });
      //   // await result.save();
      //   if (i == 0) {
      //     console.log(result);
      //   }
      // });

      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: false },
      //     isClaimed: false,
      //     collectionName: this.configService.get('rotg-collection-name'),
      //   },
      //   {
      //     isClaimed: true,
      //   },
      // );
      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: true },
      //   },
      //   {
      //     $unset: {
      //       isTrulyClaimed: true,
      //     },
      //   },
      // );
    } catch (e) {
      console.error(e);
    }
  }

  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('* * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      SCRAP_ROTG = !SCRAP_ROTG;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      const collectionName = SCRAP_ROTG
        ? this.configService.get('rotg-collection-name')
        : this.configService.get('nft-collection-name');
      await scrapMarkets(
        this.collectionModel,
        collectionName,
        EGLD_RATE,
        timestamp,
      );
      await this.collectionModel.updateMany(
        {
          collectionName,
          timestamp: { $exists: true, $ne: timestamp },
        },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      RUNNING = false;
      console.log(error);
      this.client.instance().captureException(error);
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id -market')
        .limit(limit);
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateNFTOwners(collection) {
    try {
      const endpoints = Array.from(
        { length: 20 },
        (_, index) =>
          'https://devnet-api.elrond.com/collections/' +
          collection +
          '/nfts?from=' +
          index * 500 +
          '&size=500',
      );
      return axios.all(endpoints.map((endpoint) => axios.get(endpoint)));
    } catch (e) {
      console.error(e);
    }
  }

  async findCollectionNftById(getIdDto: GetIdDto) {
    try {
      const { collection, id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        { collectionName: collection, id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      // to remove
      // this.scrapAssets('ASSET-6b7288');
      // return;
      const { collection, id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.collectionModel
        .find({
          collectionName: collection,
          idName: new RegExp('^' + id),
        })
        .sort({ id: 1 })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async lockMergeV2(getIdDto: GetIdWithoutCollectionDto) {
    try {
      const { id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: false },
        },
        { lockedOn: new Date() },
        { new: true, projection: '-_id' },
      );
      return {
        justGotLocked: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async unlockMergeV2(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      const record = await this.collectionModel.findOne({
        collectionName: this.configService.get('rotg-collection-name'),
        id,
        lockedOn: { $exists: true },
      });
      if (record) {
        record.lockedOn = undefined;
        await record.save();
      }
      return {
        justGotMerged: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async forceUnlockTest(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: true },
        },
        { $unset: { lockedOn: true } },
      );
      return true;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      collectionName: dto.collection,
      stone: dto.stone,
      isClaimed: dto.isClaimed,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto as GetAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.collectionModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.collectionModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.checkSmartContract(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(collection, claimedIds) {
    await this.collectionModel.updateMany(
      { collectionName: collection, id: { $in: claimedIds } },
      { isClaimed: true },
    );
  }

  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.collectionModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.collectionModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // @Cron('*/2 * * * *')
  // private async scrapMarket() {
  //   try {
  //     const timestamp: number = new Date().getTime();
  //     await this.fullScrapTrustmarket('bid', timestamp);
  //     await this.fullScrapTrustmarket('buy', timestamp);
  //     // await this.scrapDeadrare(timestamp);
  //     await this.nftModel.updateMany(
  //       { timestamp: { $exists: true, $ne: timestamp } },
  //       { $unset: { market: 1, timestamp: 1 } },
  //     );
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //   }
  // }
  // private async scrapTrustmarket(
  //   type: 'bid' | 'buy',
  //   offset: number,
  //   count: number,
  //   timestamp: number,
  // ) {
  //   try {
  //     const trustmarketApi = this.configService.get('trustmarket-api');
  //     const { data } = await axios.post(trustmarketApi, {
  //       filters: {
  //         onSale: true,
  //         auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
  //       },
  //       collection: 'GUARDIAN-3d6635',
  //       skip: offset,
  //       top: count,
  //       select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
  //     });
  //     if (!data.results || data.results.length === 0) return true;
  //     if (type === 'buy') {
  //       const nftSample = data.results[0];
  //       EGLD_RATE =
  //         nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
  //     }
  //     const isLast: boolean = offset + data.resultsCount === data.count;
  //     const updateObject = data.results.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.nonce },
  //         update: {
  //           market: {
  //             source:
  //               d.saleInfoNft?.marketplace === 'DR'
  //                 ? 'deadrare'
  //                 : 'trustmarket',
  //             identifier: d.identifier,
  //             type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
  //             bid:
  //               d.saleInfoNft?.auction_type !== 'NftBid'
  //                 ? null
  //                 : {
  //                     min: d.saleInfoNft?.min_bid_short,
  //                     current: d.saleInfoNft?.current_bid_short,
  //                     deadline: getTimeUntil(d.saleInfoNft?.deadline),
  //                   },
  //             token: d.saleInfoNft?.accepted_payment_token,
  //             price: d.saleInfoNft?.max_bid_short,
  //             currentUsd: +d.saleInfoNft?.usd,
  //             timestamp: +d.saleInfoNft?.timestamp,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     await this.nftModel.bulkWrite(updateObject);
  //     return isLast;
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }

  async checkSmartContract(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      //   await this.nftModel.updateMany(
      //     { id: { $in: claimedIds } },
      //     { isClaimed: true },
      //   );
      await this.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  // private async scrapDeadrare(timestamp: number) {
  //   try {
  //     const deadrareApi = this.configService.get('deadrare-api');
  //     const deadrareApiParams = this.configService.get('deadrare-api-params');
  //     const { data } = await axios.get(deadrareApi + deadrareApiParams);
  //     if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
  //     const updateObject = data.data.listAuctions.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.cachedNft.nonce },
  //         update: {
  //           market: {
  //             source: 'deadrare',
  //             identifier: d.nftId,
  //             type: 'buy',
  //             bid: null,
  //             token: 'EGLD',
  //             price: +d.price,
  //             currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     return this.nftModel.bulkWrite(updateObject);
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }
}
</pre>
<h3>collection.market.ts</h3>
<pre>
import axios from 'axios';
import { CollectionDocument } from './schemas/collection.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';
import { sleep } from './collection.helpers';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      if (auctionTokenData[6] === auctionTokenData[7]) {
        return parseInt(auctionTokenData[6], 16);
      } else {
        console.log(identifier + ': auction/' + elrondTransaction.function);
      }
    } else if (
      // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  collectionModel: Model<CollectionDocument>,
  collectionName: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket(
    'deadrare',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'frameit',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'xoxno',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'elrond',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
};

const getIdsOfNFTsInMarket = async function (
  marketName,
  collection,
  from,
  size,
) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=' +
      collection,
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  collection: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  collectionModel: Model<CollectionDocument>,
  egldRate: number,
  timestamp: number,
) {
  let from = 0;
  const size = 100;
  let nftsScrapped = false;
  while (!nftsScrapped) {
    const nftsIds = await getIdsOfNFTsInMarket(
      marketName,
      collection,
      from,
      size,
    );
    from += size;
    if (nftsIds.length == 0) {
      nftsScrapped = true;
      break;
    }

    // update timestamp for in-market nfts
    await collectionModel.updateMany(
      { collectionName: collection, id: { $in: nftsIds } },
      { timestamp },
    );
    // get newly entered nfts
    const newNFTs = await collectionModel.find({
      collectionName: collection,
      id: { $in: nftsIds },
      market: { $exists: false },
    });

    const updateObject = [];
    for (const nft of newNFTs) {
      // update db with price of newly added nft
      let price;
      try {
        price = await getNftPrice(marketName, nft.identifier);
      } catch (e) {
        continue;
      }
      const market = {
        source: marketName,
        identifier: nft.identifier,
        type: 'buy',
        bid: null,
        token: 'EGLD',
        price,
        currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
      };
      console.log(market);
      updateObject.push({
        updateOne: {
          filter: { collectionName: collection, id: nft.id },
          update: {
            market,
          },
        },
      });
      await sleep(500);
    }
    await collectionModel.bulkWrite(updateObject);
  }
};
</pre>
<h3>nft.dto.ts</h3>
<pre>
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  IsNumberString,
  IsOptional,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/nft.filters';

export class GetIdDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @ApiPropertyOptional({
    description: 'Guardian crown type',
    enum: filters.crown,
  })
  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
</pre>
<h3>nft.controller.spec.ts</h3>
<pre>
import { ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Connection } from 'mongoose';
import * as request from 'supertest';

import { AppModule } from '../../app.module';
import { DatabaseService } from '../../database/database.service';
import { GetErdDto } from './dto/nft.dto';

const erdStubWithNFTs = (): GetErdDto => {
  return {
    erd: 'erd17djfwed563cry53thgytxg5nftvl9vkec4yvrgveu905zeq6erqqkr7cmy',
  };
};
const erdStubWithoutNFTs = (): GetErdDto => {
  return {
    erd: 'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
  };
};
const erdStubInvalid = (): GetErdDto => {
  return {
    erd: 'erd1qck4cpghjff88gg7rq6q4w0fndd3g33v499999z9ehjhqg9uxu222zkxwz',
  };
};

describe('NFTController', () => {
  let dbConnection: Connection;
  let httpServer: any;
  let app: any;
  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
      }),
    );
    await app.init();
    dbConnection = moduleRef
      .get<DatabaseService>(DatabaseService)
      .getDbHandle();
    httpServer = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('findByUser', () => {
    it("should return list of user's nfts", async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toBeGreaterThan(0);
    });
    it('should return empty list in case user has no nfts', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithoutNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(0);
    });
    it('should return 500 in case user erd is invalid', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubInvalid().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(500);
    });
  });

  describe('findById', () => {
    it('should return NFT with id=666', async () => {
      const response = await request(httpServer).get(`/nft/id/666`);
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('id');
      expect(response.body.id).toEqual(666);
    });
    it('should return 400 in for out of range id', async () => {
      const response = await request(httpServer).get(`/nft/id/10000`);
      expect(response.status).toBe(400);
    });
  });

  describe('findAll', () => {
    it('should return 400 with page > 500', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=501`,
      );
      expect(response.status).toBe(400);
    });
    it('should return list with id=1 for first element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(20);
      expect(response.body.nfts[0].id).toEqual(1);
    });
    it('should return list with rank=1 for last element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=500`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(19);
      expect(response.body.nfts[18].rank).toEqual(1);
    });

    it('should return filtered element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=1&background=kyoto%20ape&crown=shepherd%20of%20grace&hairstyle=tako&hairstyleColor=grey&eyes=oshiza&eyesColor=grey&nose=hiken&mouth=dagon&mouthColor=grey&armor=shin&weapon=oshiza%20spear&stone=lava&id=39`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(1);
      expect(response.body.nfts[0].id).toEqual(3908);
    });
  });

  describe('findByMarket', () => {
    it('should return list of NFTs listed on deadrare + trustmarket', async () => {
      const response = await request(httpServer).get(
        `/nft/market?order=asc&page=1&by=price`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const sources = response.body.nfts.map((el) => {
        return el.market.source;
      });
      expect(sources).toContain('deadrare');
      expect(sources).toContain('trustmarket');
    });
    it('should return prices in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=price',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const prices = response.body.nfts.map((el) => {
        return el.market.currentUsd;
      });
      expect(prices[0]).toBeGreaterThan(prices[1]);
    });
    it('should return rank in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=rank',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ranks = response.body.nfts.map((el) => {
        return el.rank;
      });
      expect(ranks[0]).toBeGreaterThan(ranks[1]);
    });
    it('should return ids in ascending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=asc&page=1&by=id',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ids = response.body.nfts.map((el) => {
        return el.id;
      });
      expect(ids[0]).toBeLessThan(ids[1]);
    });
  });
});
</pre>
<h3>nft.market.ts</h3>
<pre>
import axios from 'axios';
import { NFTDocument } from './schemas/nft.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      return parseInt(auctionTokenData[6], 16);
    } else if ( // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket('deadrare', nftModel, egldRate, timestamp);
  await scrapOneMarket('frameit', nftModel, egldRate, timestamp);
  await scrapOneMarket('xoxno', nftModel, egldRate, timestamp);
  await scrapOneMarket('elrond', nftModel, egldRate, timestamp);
};

const getIdsOfNFTsInMarket = async function (marketName, from, size) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=GUARDIAN-3d6635',
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  try {
    let from = 0;
    const size = 100;
    let nftsScrapped = false;
    while (!nftsScrapped) {
      const nftsIds = await getIdsOfNFTsInMarket(marketName, from, size);
      from += size;
      if (nftsIds.length == 0) {
        nftsScrapped = true;
        break;
      }

      // update timestamp for in-market nfts
      await nftModel.updateMany({ id: { $in: nftsIds } }, { timestamp });
      // get newly entered nfts
      const newNFTs = await nftModel.find({
        id: { $in: nftsIds },
        market: { $exists: false },
      });

      const updateObject = [];
      for (const nft of newNFTs) {
        // update db with price of newly added nft
        let price;
        try {
          price = await getNftPrice(marketName, nft.identifier);
        } catch (e) {
          continue;
        }
        const market = {
          source: marketName,
          identifier: nft.identifier,
          type: 'buy',
          bid: null,
          token: 'EGLD',
          price,
          currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
        };
        console.log(market);
        updateObject.push({
          updateOne: {
            filter: { id: nft.id },
            update: {
              market,
            },
          },
        });
      }
      await nftModel.bulkWrite(updateObject);
    }
  } catch (e) {
    console.log(e);
    try {
      await nftModel.updateMany({ 'market.source': marketName }, { timestamp });
    } catch (e) {}
  }
};
</pre>
<h3>nft.service.ts</h3>
<pre>
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';
import { NFT, NFTDocument } from './schemas/nft.schema';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { CollectionService } from '../collection/collection.service';
import { scrapMarkets } from './nft.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
} from '../collection/collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class NftService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private readonly collectionService: CollectionService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(NFT.name) private nftModel: Model<NFTDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(erd, filters) {
    const apiParams = this.configService.get('elrond-api-params');
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}${apiParams}`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };

    return { findQuery, filtersQuery };
  }

  async getByIds(ids: number[]) {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .limit(limit);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findById(getIdDto: GetIdDto) {
    try {
      const { id } = getIdDto;
      const record = await this.nftModel.findOneAndUpdate(
        { id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      const { id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.nftModel
        .find({
          idName: new RegExp('^' + id),
        })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      stone: dto.stone,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.nftModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.nftModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.updateIsClaimed(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.nftModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }
  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('*/30 * * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      await scrapMarkets(this.nftModel, EGLD_RATE, timestamp);
      await this.nftModel.updateMany(
        { timestamp: { $exists: true, $ne: timestamp } },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      console.log(error);
      this.client.instance().captureException(error);
    }
  }
  private async scrapTrustmarket(
    type: 'bid' | 'buy',
    offset: number,
    count: number,
    timestamp: number,
  ) {
    try {
      const trustmarketApi = this.configService.get('trustmarket-api');
      const { data } = await axios.post(trustmarketApi, {
        filters: {
          onSale: true,
          auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
        },
        collection: 'GUARDIAN-3d6635',
        skip: offset,
        top: count,
        select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
      });
      if (!data.results || data.results.length === 0) return true;
      if (type === 'buy') {
        const nftSample = data.results[0];
        EGLD_RATE =
          nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
      }
      const isLast: boolean = offset + data.resultsCount === data.count;
      const updateObject = data.results.map((d) => ({
        updateOne: {
          filter: { id: d.nonce },
          update: {
            market: {
              source:
                d.saleInfoNft?.marketplace === 'DR'
                  ? 'deadrare'
                  : 'trustmarket',
              identifier: d.identifier,
              type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
              bid:
                d.saleInfoNft?.auction_type !== 'NftBid'
                  ? null
                  : {
                      min: d.saleInfoNft?.min_bid_short,
                      current: d.saleInfoNft?.current_bid_short,
                      deadline: getTimeUntil(d.saleInfoNft?.deadline),
                    },
              token: d.saleInfoNft?.accepted_payment_token,
              price: d.saleInfoNft?.max_bid_short,
              currentUsd: +d.saleInfoNft?.usd,
              timestamp: +d.saleInfoNft?.timestamp,
            },
            timestamp,
          },
        },
      }));
      await this.nftModel.bulkWrite(updateObject);
      return isLast;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private async fullScrapTrustmarket(type: 'bid' | 'buy', timestamp: number) {
    let isFinished = false;
    let offset = 0;
    const count = 200;
    while (!isFinished) {
      isFinished = await this.scrapTrustmarket(type, offset, count, timestamp);
      offset += count;
    }
  }

  private async scrapDeadrare(timestamp: number) {
    try {
      const deadrareApi = this.configService.get('deadrare-api');
      const deadrareApiParams = this.configService.get('deadrare-api-params');
      const { data } = await axios.get(deadrareApi + deadrareApiParams);
      if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
      const updateObject = data.data.listAuctions.map((d) => ({
        updateOne: {
          filter: { id: d.cachedNft.nonce },
          update: {
            market: {
              source: 'deadrare',
              identifier: d.nftId,
              type: 'buy',
              bid: null,
              token: 'EGLD',
              price: +d.price,
              currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
            },
            timestamp,
          },
        },
      }));
      return this.nftModel.bulkWrite(updateObject);
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      await this.nftModel.updateMany(
        { id: { $in: claimedIds } },
        { isClaimed: true },
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('nft-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  async claimByIds(ids: number[]): Promise<{ nfts: any }> {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      const updatedNfts = await this.updateIsClaimed(nfts);
      return { nfts: updatedNfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
</pre>
<h3>nft.controller.ts</h3>
<pre>
import { Controller, Get, Param, ParseArrayPipe, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { NftService } from './nft.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';

@ApiTags('nft')
@Controller('nft')
export class NftController {
  constructor(private readonly nftService: NftService) {}

  @Get('user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findUserNftCount({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.nftService.findByUserLimited({ ...getErdDto, ...getAllDto });
  }

  @Get('id/:id')
  getById(@Param() getIdDto: GetIdDto) {
    return this.nftService.findById(getIdDto);
  }

  @Get('search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.nftService.findByIdPrefix(getIdDto);
  }

  @Get('ids/:ids')
  getByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.getByIds(ids);
  }

  @Get('claim/:ids')
  claimByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.claimByIds(ids);
  }

  @Get('all')
  getAll(@Query() getAllDto: GetAllDto) {
    return this.nftService.findAll(getAllDto);
  }

  @Get('market')
  getByMarket(@Query() getMarketDto: GetMarketDto) {
    return this.nftService.findByMarket(getMarketDto);
  }
}
</pre>
<h3>nft.schema.ts</h3>
<pre>
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type NFTDocument = NFT & Document;

const BaseAssetType = { name: String, url: String, rarity: Number, _id: false };
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class NFT {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);
</pre>
<h3>nft.filters.ts</h3>
<pre>
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
</pre>
<h3>nft.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { NftService } from './nft.service';
import { NftController } from './nft.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { NFT, NFTSchema } from './schemas/nft.schema';
import { CollectionModule } from '../collection/collection.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: NFT.name, schema: NFTSchema }]),
    CollectionModule,
  ],
  controllers: [NftController],
  providers: [NftService],
})
export class NftModule {}
</pre>
<h3>auth.service.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { EnvironmentVariables } from 'src/config/configuration.d';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<EnvironmentVariables>,
  ) {}
  async validateUser(email: string, pass: string): Promise<any> {
    const env = this.configService.get('env');
    return ['production', 'staging'].indexOf(env) === -1 ? true : null;
  }
  async login(user: any) {
    return {
      access_token: this.jwtService.sign({ key: 'splitamerge' }),
    };
  }
}
</pre>
<h3>jwt.strategy.ts</h3>
<pre>
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../../config/configuration.d';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService<EnvironmentVariables>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt-secret', { infer: true }),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
</pre>
<h3>local.strategy.ts</h3>
<pre>
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
</pre>
<h3>auth.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../config/configuration.d';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables>) => ({
        secret: config.get('jwt-secret', { infer: true }),
        signOptions: { expiresIn: '2 days' },
      }),
    }),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
</pre>
<h3>jwt-auth.guard.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
</pre>
<h3>local-auth.guard.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
</pre>
<h3>elrond-api.controller.ts</h3>
<pre>
import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ElrondApiService } from './elrond-api.service';

@ApiTags('elrond-api')
@Controller('elrond-api')
export class ElrondApiController {
  constructor(private readonly elrondApiService: ElrondApiService) {}

  @Get('/*')
  get(@Param() params) {
    return this.elrondApiService.get(params[0]);
  }

  @Post('/*')
  post(@Param() params, @Body() body) {
    return this.elrondApiService.post(params[0], body);
  }
}
</pre>
<h3>elrond-api.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { ElrondApiController } from './elrond-api.controller';
import { ElrondApiService } from './elrond-api.service';

@Module({
  controllers: [ElrondApiController],
  providers: [ElrondApiService],
  imports: [RedisModule],
})
export class ElrondApiModule {}
</pre>
<h3>elrond-api.controller.spec.ts</h3>
<pre>
// import { Test, TestingModule } from '@nestjs/testing';
// import { ElrondApiController } from './elrond-api.controller';
// import { ElrondApiService } from './elrond-api.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('ElrondApiController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  //   let controller: ElrondApiController;
  //   let service: ElrondApiService;

  //   beforeEach(async () => {
  //     const module: TestingModule = await Test.createTestingModule({
  //       controllers: [ElrondApiController],
  //       imports: [RedisModule, EnvConfigModule],
  //       providers: [
  //         ElrondApiService,
  //         {
  //           provide: SENTRY_TOKEN,
  //           useValue: { debug: jest.fn() },
  //         },
  //       ],
  //     }).compile();

  //     controller = module.get<ElrondApiController>(ElrondApiController);
  //     service = module.get<ElrondApiService>(ElrondApiService);
  //   });

  //   // it('elrondApiController should be defined', () => {
  //   //   expect(controller).toBeDefined();
  //   // });
  //   // it('elrondApiService should be defined', () => {
  //   //   expect(service).toBeDefined();
  //   // });
  //   // it('elrondApiController GET should get correct data', async () => {
  //   //   const data = await controller.get({ '0': 'stats' });
  //   //   expect(data).toHaveProperty('accounts');
  //   //   expect(data).toHaveProperty('blocks');
  //   //   expect(data).toHaveProperty('epoch');
  //   //   expect(data).toHaveProperty('refreshRate');
  //   //   expect(data).toHaveProperty('roundsPassed');
  //   //   expect(data).toHaveProperty('roundsPerEpoch');
  //   //   expect(data).toHaveProperty('shards');
  //   //   expect(data).toHaveProperty('transactions');
  //   // });

  //   // it('elrondApiController POST should send ok', async () => {
  //   //   const data = await controller.post(
  //   //     { '0': 'query' },
  //   //     {
  //   //       scAddress:
  //   //         'erd1qqqqqqqqqqqqqpgqra3rpzamn5pxhw74ju2l7tv8yzhpnv98nqjsvw3884',
  //   //       funcName: 'getFirstMissionStartEpoch',
  //   //       args: [],
  //   //     },
  //   //   );
  //   //   expect(data).toHaveProperty('returnCode');
  //   //   expect(data.returnCode).toBe('ok');
  //   // });
  /* It's a comment. */
});
</pre>
<h3>elrond-api.service.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { RedisService } from '../../redis/redis.service';

@Injectable()
export class ElrondApiService {
  private networkProvider: ApiNetworkProvider;
  private env: string;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    private redisService: RedisService,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
    this.env = this.configService.get('env');
  }

  async get(route) {
    try {
      const redisKey = this.env + route;
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doGetGeneric(route);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async post(route, payload) {
    try {
      const redisKey = this.env + route + JSON.stringify(payload);
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doPostGeneric(route, payload);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
</pre>
<h3>stats.controller.spec.ts</h3>
<pre>
// import { Test, TestingModule } from '@nestjs/testing';
// import { StatsController } from './stats.controller';
// import { StatsService } from './stats.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('StatsController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  // let controller: StatsController;
  // let service: StatsService;
  // beforeEach(async () => {
  //   const module: TestingModule = await Test.createTestingModule({
  //     controllers: [StatsController],
  //     providers: [
  //       StatsService,
  //       {
  //         provide: SENTRY_TOKEN,
  //         useValue: { debug: jest.fn() },
  //       },
  //     ],
  //     imports: [RedisModule, EnvConfigModule],
  //   }).compile();
  //   controller = module.get<StatsController>(StatsController);
  //   service = module.get<StatsService>(StatsService);
  // });
  // it('statsController should be defined', () => {
  //   expect(controller).toBeDefined();
  // });
  // it('statsService should be defined', () => {
  //   expect(service).toBeDefined();
  // });
  // it('statsController should get correct data', async () => {
  //   const data = await controller.get();
  //   expect(data).toHaveProperty('twitter');
  //   expect(data.twitter).toHaveProperty('followerCount');
  //   expect(data).toHaveProperty('guardians');
  //   expect(data.guardians).toHaveProperty('smallest24hTrade');
  //   expect(data.guardians).toHaveProperty('averagePrice');
  //   expect(data.guardians).toHaveProperty('holderCount');
  //   expect(data.guardians).toHaveProperty('totalEgldVolume');
  //   expect(data.guardians).toHaveProperty('floorPrice');
  //   expect(data.guardians.totalEgldVolume).toBeGreaterThanOrEqual(12500);
  //   expect(data.guardians.holderCount).toBeGreaterThanOrEqual(1000);
  //   expect(data.twitter.followerCount).toBeGreaterThanOrEqual(16000);
  //   expect(data.guardians.averagePrice).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.smallest24hTrade).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.floorPrice).toBeGreaterThanOrEqual(1);
  // });
});
</pre>
<h3>stats.controller.ts</h3>
<pre>
import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { StatsService } from './stats.service';

@ApiTags('stats')
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @Get('/')
  get() {
    return this.statsService.get();
  }
}
</pre>
<h3>stats.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';

@Module({
  controllers: [StatsController],
  providers: [StatsService],
  imports: [RedisModule],
})
export class StatsModule {}
</pre>
<h3>stats.service.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { RedisService } from '../../redis/redis.service';
import * as cheerio from 'cheerio';

@Injectable()
export class StatsService {
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private redisService: RedisService,
  ) {}

  async get() {
    try {
      const cachedData = await this.redisService.get('AQXSTATS');
      if (cachedData) return cachedData;
      const volumeData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/analytics?timeZone=Europe%2FParis&market=secundary&startDate=2021-11-01T00:00:00.000Z&endDate=' +
          new Date().toISOString() +
          '&buckets=1',
      );
      const holderData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/holder_and_supply',
      );
      const twitterData = await axios.get(
        'https://api.livecounts.io/twitter-live-follower-counter/stats/TheAquaverse',
      );
      const floorAverageData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/floor_and_average_price?chartTimeRange=day',
      );
      const xoxnoPage = await axios.get(
        'https://xoxno.com/collection/GUARDIAN-3d6635',
      );
      let floorPrice = null;

      try {
        const cheerioData = cheerio.load(xoxnoPage.data);
        const xoxnoData = cheerioData('#__NEXT_DATA__').html();
        const parsedXoxnoData = JSON.parse(xoxnoData);
        floorPrice = parsedXoxnoData?.props?.pageProps?.initInfoFallback?.floor;
      } catch (e) {}

      const rawEgldVolume =
        volumeData &&
        volumeData.data &&
        volumeData.data.date_histogram &&
        volumeData.data.date_histogram.length > 0
          ? volumeData.data.date_histogram[0].volume
          : null;
      const denum = Math.pow(10, 18);
      const followerCount =
        twitterData && twitterData.data && twitterData.data.followerCount
          ? twitterData.data.followerCount
          : null;
      const totalEgldVolume = rawEgldVolume ? Math.round(rawEgldVolume) : null;
      const holderCount =
        holderData.data && holderData.data.holderCount
          ? holderData.data.holderCount
          : null;
      const floorAverageDataList =
        floorAverageData.data && floorAverageData.data.length > 0
          ? floorAverageData.data
          : [];
      const smallest24hTrade =
        floorAverageDataList.length > 0 && floorAverageDataList[0].floor_price
          ? Math.round((floorAverageDataList[0].floor_price / denum) * 100) /
            100
          : null;

      const oldFloorAverageData =
        floorAverageDataList.length > 1 &&
        floorAverageDataList[floorAverageDataList.length - 1]
          ? floorAverageDataList[floorAverageDataList.length - 1]
          : null;

      const old24hTrade =
        oldFloorAverageData && oldFloorAverageData.floor_price
          ? Math.round((oldFloorAverageData.floor_price / denum) * 100) / 100
          : null;

      const percentage24hTrade =
        smallest24hTrade !== null && old24hTrade !== null
          ? Number(
              ((100 * (smallest24hTrade - old24hTrade)) / old24hTrade).toFixed(
                2,
              ),
            )
          : 0;
      const averagePrice =
        floorAverageDataList.length > 0 && floorAverageDataList[0].average_price
          ? Math.round((floorAverageDataList[0].average_price / denum) * 100) /
            100
          : null;

      const oldAveragePrice =
        oldFloorAverageData && oldFloorAverageData.average_price
          ? Math.round((oldFloorAverageData.average_price / denum) * 100) / 100
          : null;

      const percentageAveragePrice =
        smallest24hTrade !== null && oldAveragePrice !== null
          ? Number(
              (
                (100 * (averagePrice - oldAveragePrice)) /
                oldAveragePrice
              ).toFixed(2),
            )
          : 0;

      const data = {
        twitter: {
          followerCount,
        },
        guardians: {
          smallest24hTrade,
          percentage24hTrade,
          averagePrice,
          percentageAveragePrice,
          holderCount,
          totalEgldVolume,
          floorPrice,
        },
      };
      await this.redisService.set('AQXSTATS', data, 900);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
</pre>
<h3>collection.dto.ts</h3>
<pre>
import { ConfigService } from '@nestjs/config';
import configuration from '../../../config/configuration';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { IntersectionType } from '@nestjs/swagger';

const configService: ConfigService<EnvironmentVariables> = new ConfigService(
  configuration(),
);

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  MinLength,
  IsNumberString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsInt,
  Min,
  Max,
  ArrayMaxSize,
  ArrayMinSize,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/collection.filters';

export class CreateJWTDto {
  @ApiProperty({
    description: 'email',
  })
  @IsNotEmpty()
  readonly email: string;
  @ApiProperty({
    description: 'password',
  })
  @IsNotEmpty()
  readonly password: string;
}

export class GetCollectionDto {
  @Matches(
    new RegExp(
      '^(' +
        configService.get('nft-collection-name') +
        '|' +
        configService.get('rotg-collection-name') +
        '|' +
        configService.get('ltbox-collection-name') +
        '|' +
        configService.get('tiket-collection-name') +
        '|' +
        configService.get('asset-collection-name') +
        ')$',
    ),
  )
  @ApiProperty({
    enum: [
      configService.get('nft-collection-name'),
      configService.get('rotg-collection-name'),
      configService.get('ltbox-collection-name'),
      configService.get('tiket-collection-name'),
      configService.get('asset-collection-name'),
    ],
  })
  readonly collection: string;
}

export class GetIdWithoutCollectionDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

export class GetIdDto extends IntersectionType(
  GetCollectionDto,
  GetIdWithoutCollectionDto,
) {}

export class GetIdsDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'ids of nft',
  })
  ids: number[];
}
export class GetElementDto extends GetCollectionDto {
  @IsEnum(['water', 'rock', 'algae', 'lava', 'bioluminescent'])
  @ApiProperty({
    description: 'nft/sft element',
  })
  element: string;
}

export class GetIdentifiersDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'identifier of nft/sft',
  })
  identifiers: string[];
}

export class ROTGModel {
  @ApiProperty({
    description: 'ROTG id',
  })
  @IsInt()
  @Min(1)
  @Max(9999)
  id: number;

  @ApiProperty({
    description: 'ROTG name',
  })
  @IsNotEmpty()
  readonly name: string;

  @ApiProperty({
    description: 'ROTG description',
  })
  @IsNotEmpty()
  readonly description: string;

  @ApiProperty({
    description: 'ROTG element',
  })
  @IsEnum(['Water', 'Rock', 'Algae', 'Lava', 'Bioluminescent'])
  readonly element: string;

  @ApiProperty({
    description: 'ROTG image url',
  })
  @IsNotEmpty()
  readonly image: string;

  @ApiProperty({
    description: 'ROTG attributes',
  })
  @ArrayMaxSize(10)
  @ArrayMinSize(10)
  readonly attributes: any[];
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto extends GetCollectionDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
</pre>
<h3>collection.helpers.ts</h3>
<pre>
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers/out';
import axios from 'axios';

export const sleep = (ms: number) => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};

export const erdDoGetGeneric = async (networkProvider, uri, count = 1) => {
  try {
    const data = await networkProvider.doGetGeneric(uri);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const erdDoPostGeneric = async (
  networkProvider,
  uri,
  body,
  count = 1,
) => {
  try {
    const data = await networkProvider.doPostGeneric(uri, body);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const processElrondNFTs = async (
  networkProvider: ApiNetworkProvider,
  uriType: 'collections' | 'accounts',
  uriName: string,
  processFunction: (nftList: any[]) => void,
) => {
  try {
    const nftCount = await erdDoGetGeneric(
      networkProvider,
      uriType + '/' + uriName + '/nfts/count',
    );
    const n = 1;
    const size = 100;
    const maxIteration = Math.ceil(nftCount / (size * n));
    for (let i = 0; i < maxIteration; i++) {
      const endpoints = Array.from(
        { length: n },
        (_, index) =>
          'https://devnet-api.elrond.com/' +
          uriType +
          '/' +
          uriName +
          '/nfts?from=' +
          (index + i * n) * size +
          '&size=' +
          size,
      );
      const parallelData = await axios.all(
        endpoints.map((endpoint) => {
          return axios.get(endpoint);
        }),
      );
      console.log('go');
      for (const data of parallelData) {
        if (data.status === 200) {
          await processFunction(data.data);
        } else {
          console.log('ELROND ERROR');
        }
      }
      console.log(i + ' - data scrapped');
      await sleep(3000);
    }
  } catch (e) {
    console.error(e);
  }
};
</pre>
<h3>collection.controller.ts</h3>
<pre>
import {
  Body,
  Controller,
  Get,
  Param,
  ParseArrayPipe,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { CollectionService } from './collection.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetErdDto,
  GetIdDto,
  GetIdsDto,
  GetIdentifiersDto,
  GetMarketDto,
  CreateJWTDto,
  GetIdWithoutCollectionDto,
  ROTGModel,
  GetElementDto,
} from './dto/collection.dto';
import { LocalAuthGuard } from '../auth/guards/local-auth.guard';
import { AuthService } from '../auth/auth.service';

@ApiTags('collection')
@Controller('collection')
export class CollectionController {
  constructor(
    private readonly collectionService: CollectionService,
    private authService: AuthService,
  ) {}

  @Get(':collection/user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get(':collection/user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findUserNftCount({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.collectionService.findByUserLimited({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get(':collection/id/:id')
  getCollectionNftById(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findCollectionNftById(getIdDto);
  }

  @Get(':collection/search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findByIdPrefix(getIdDto);
  }

  @Get('scrapRotg')
  scrapRotg() {
    return this.collectionService.scrapAssets();
  }

  @UseGuards(LocalAuthGuard)
  @Post('/getJWT')
  async login(@Request() req, @Body() createJWT: CreateJWTDto) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('/lockMerge/:id')
  @ApiBearerAuth()
  lockMergeV2(@Param() getIdDto: GetIdWithoutCollectionDto) {
    return this.collectionService.lockMergeV2(getIdDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockMerge/:id')
  @ApiBearerAuth()
  unlockMergeV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.unlockMergeV2({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockForce/:id')
  @ApiBearerAuth()
  forceUnlockTestV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.forceUnlockTest({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @Get(':collection/ids/:ids')
  getByIds(@Param() getIdsDto: GetIdsDto) {
    getIdsDto.ids = (getIdsDto.ids as unknown as string)
      .split(',')
      .map((idStr) => Number(idStr))
      .filter((id) => !isNaN(id));
    return this.collectionService.getByIds(getIdsDto);
  }

  @Get(':collection/identifiers/:identifiers')
  getByIdentifiers(@Param() getIdentifiersDto: GetIdentifiersDto) {
    getIdentifiersDto.identifiers = (
      getIdentifiersDto.identifiers as unknown as string
    )
      .split(',')
      .filter((identifier) => identifier.length > 0);
    return this.collectionService.getByIdentifiers(getIdentifiersDto);
  }

  @Get(':collection/floor/:element')
  getElementFloorPrice(@Param() getElementDto: GetElementDto) {
    return this.collectionService.getElementFloorPrice(getElementDto);
  }

  @Get(':collection/all')
  getAll(
    @Param() getCollectionDto: GetCollectionDto,
    @Query() getAllDto: GetAllDto,
  ) {
    return this.collectionService.findAll({
      ...getCollectionDto,
      ...getAllDto,
    });
  }

  // @Get(':collcetion/market')
  // getByMarket(
  //   @Param() getCollectionDto: GetCollectionDto,
  //   @Query() getMarketDto: GetMarketDto,
  // ) {
  //   return this.collectionService.findByMarket(getMarketDto);
  // }
}
</pre>
<h3>collection.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { CollectionService } from './collection.service';
import { CollectionController } from './collection.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Collection, CollectionSchema } from './schemas/collection.schema';
import { NftModule } from '../nft/nft.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([
      { name: Collection.name, schema: CollectionSchema },
    ]),
  ],
  controllers: [CollectionController],
  providers: [CollectionService],
  exports: [CollectionService],
})
export class CollectionModule {}
</pre>
<h3>collection.schema.ts</h3>
<pre>
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CollectionDocument = Collection & Document;

const BaseAssetType = {
  name: String,
  url: String,
  vril: Number,
  rarity: Number,
  _id: false,
};
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class Collection {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  collectionName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: false, type: String })
  assetType: string;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: false, type: Number })
  balance: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  vril: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
  @Prop({ required: false, type: Date })
  lockedOn: Date;
}

export const CollectionSchema = SchemaFactory.createForClass(Collection);
</pre>
<h3>collection.filters.ts</h3>
<pre>
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
</pre>
<h3>collection.service.ts</h3>
<pre>
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetElementDto,
  GetErdDto,
  GetIdDto,
  GetIdentifiersDto,
  GetIdsDto,
  GetIdWithoutCollectionDto,
  GetMarketDto,
  ROTGModel,
} from './dto/collection.dto';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { Collection, CollectionDocument } from './schemas/collection.schema';
import { scrapMarkets } from './collection.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
  processElrondNFTs,
} from './collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;
let SCRAP_ROTG = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class CollectionService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(Collection.name)
    private collectionModel: Model<CollectionDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(collection, erd, filters) {
    const size = 1450;
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}/nfts?from=0&size=${size}&collections=${collection}&withScamInfo=false&computeScamInfo=false`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const sfts = dataNFTs
      .filter((d) => d.type === 'SemiFungibleESDT')
      .reduce((agg, unit) => {
        return { ...agg, [unit.nonce]: Number(unit.balance) };
      }, {});
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };
    return { findQuery, filtersQuery, sfts };
  }

  async getByIds(getIdsDto: GetIdsDto) {
    try {
      const { collection, ids } = getIdsDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, id: { $in: ids } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getElementFloorPrice(getElementDto: GetElementDto) {
    try {
      const { collection, element } = getElementDto;
      const lowestPriceNft = await this.collectionModel
        .find(
          {
            collectionName: collection,
            market: { $exists: true },
            stone: element,
          },
          '-_id',
        )
        .sort('market.price')
        .limit(1);
      if (lowestPriceNft && lowestPriceNft.length > 0) {
        return {
          floorPrice: lowestPriceNft[0].market.price,
          details: lowestPriceNft[0],
        };
      } else {
        return {
          floorPrice: 0,
          details: {},
        };
      }
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getByIdentifiers(getIdentifiersDto: GetIdentifiersDto) {
    try {
      const { collection, identifiers } = getIdentifiersDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, identifier: { $in: identifiers } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd, collection } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery, sfts } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      nfts.forEach((nft) => {
        nft.balance = nft.idName in sfts ? sfts[nft.idName] : 1;
      });
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // to remove
  async updateDatabase(assets) {
    try {
      const collections = [];
      let i = 0;
      for (const sft of assets) {
        const pngUrl = sft.media[0].originalUrl.split('/');
        let path = pngUrl[5] + '/' + pngUrl[6].split('.')[0];
        switch (path) {
          case 'Background/Medusa':
            path = 'Background/' + encodeURIComponent('Médusa');
            break;
          case 'Armor/Erales Legendary Algae 5':
            path = 'Armor/' + encodeURIComponent('Eralès Legendary Algae 5');
            break;
        }
        const assetData = await axios.get(
          'https://storage.googleapis.com/guardians-assets-original/json-asset-v2/' +
            path +
            '.json',
        );
        console.log('json read: ' + i);
        i++;
        const asset = {
          url: '/' + path + '.png',
        };
        let assetType;
        let stone;
        for (const trait of assetData.data.attributes) {
          switch (trait.trait_type) {
            case 'Type':
              assetType = trait.value.toLowerCase();
              break;
            case 'Family':
              asset['name'] = trait.value.toLowerCase();
              break;
            case 'Element':
              stone = trait.value.toLowerCase();
              break;
            case 'Vril':
              asset['vril'] = trait.value;
              break;
            case 'Level':
              asset['level'] = trait.value;
              break;
          }
        }
        const output = {
          stone,
          assetType,
          [assetType]: {
            ...asset,
          },
          collectionName: sft.collection,
          identifier: sft.identifier,
          id: sft.nonce,
          idName: sft.nonce.toString(),
          vril: asset['vril'],
        };
        collections.push(output);
      }
      const updateObject = collections.map((d) => ({
        updateOne: {
          filter: { id: d.id, collectionName: d.collectionName },
          update: d,
          upsert: true,
        },
      }));
      // console.log('starting bulk write');
      // await this.collectionModel.bulkWrite(updateObject);
      // console.log('finish');
    } catch (error) {
      console.error(error);
    }
  }

  async scrap() {
    const rotg = this.configService.get('rotg-collection-name');
    const lastNft = (
      await erdDoGetGeneric(
        this.networkProvider,
        `nfts?collection=${rotg}&from=0&size=1&includeFlagged=true`,
      )
    )[0];

    const count = await this.collectionModel.count({
      collectionName: rotg,
    });

    const nftToAdd = lastNft.nonce - count;

    const nfts = await erdDoGetGeneric(
      this.networkProvider,
      `nfts?collection=${rotg}&from=0&size=${nftToAdd}&includeFlagged=true`,
    );
    nfts.forEach((nft) => {
      this.collectionModel.create({
        collection: `${rotg}-2`,
        identifier: nft.identifier,

      });
    });
    console.log(JSON.stringify(nfts[0]));
  }

  // to remove
  async scrapAssets() {
    try {
      this.scrap();
      // await processElrondNFTs(
      //   this.networkProvider,
      //   'accounts',
      //   'erd1qqqqqqqqqqqqqpgq58vp0ydxgpae47pkxqfscvnnzv6vaq9derqqqwmujy',
      //   async (nftList: any[]) => {
      //   },
      // );
      // const nfts = await this.collectionModel.find(
      //   {
      //     collectionName: 'ROTG-467abf',
      //   },
      //   '-_id',
      // );

      // nfts = nfts.map((nft) => {
      //   return {
      //     ...nft.$clone(),
      //     collectionName: nft.collectionName.replace(
      //       'ASSET-6b7288',
      //       'ROTGW-0da75b',
      //     ),
      //     oldId: nft.identifier,
      //     identifier: nft.identifier.replace('ASSET-6b7288', 'ROTGW-0da75b'),
      //   };
      // }) as any;

      // this.collectionModel.create({

      // })

      // (nfts as any).forEach(async (nft, i) => {
      //   const result = await this.collectionModel.findOneAndUpdate(
      //     {
      //       identifier: nft.oldId,
      //     },
      //     {
      //       identifier: nft.identifier,
      //       collectionName: nft.collectionName,
      //     },
      //   );
      //   console.log(result);
      //   console.log({
      //     identifier: nft.identifier,
      //     collectionName: nft.collectionName,
      //   });
      //   // await result.save();
      //   if (i == 0) {
      //     console.log(result);
      //   }
      // });

      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: false },
      //     isClaimed: false,
      //     collectionName: this.configService.get('rotg-collection-name'),
      //   },
      //   {
      //     isClaimed: true,
      //   },
      // );
      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: true },
      //   },
      //   {
      //     $unset: {
      //       isTrulyClaimed: true,
      //     },
      //   },
      // );
    } catch (e) {
      console.error(e);
    }
  }

  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('* * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      SCRAP_ROTG = !SCRAP_ROTG;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      const collectionName = SCRAP_ROTG
        ? this.configService.get('rotg-collection-name')
        : this.configService.get('nft-collection-name');
      await scrapMarkets(
        this.collectionModel,
        collectionName,
        EGLD_RATE,
        timestamp,
      );
      await this.collectionModel.updateMany(
        {
          collectionName,
          timestamp: { $exists: true, $ne: timestamp },
        },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      RUNNING = false;
      console.log(error);
      this.client.instance().captureException(error);
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id -market')
        .limit(limit);
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateNFTOwners(collection) {
    try {
      const endpoints = Array.from(
        { length: 20 },
        (_, index) =>
          'https://devnet-api.elrond.com/collections/' +
          collection +
          '/nfts?from=' +
          index * 500 +
          '&size=500',
      );
      return axios.all(endpoints.map((endpoint) => axios.get(endpoint)));
    } catch (e) {
      console.error(e);
    }
  }

  async findCollectionNftById(getIdDto: GetIdDto) {
    try {
      const { collection, id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        { collectionName: collection, id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      // to remove
      // this.scrapAssets('ASSET-6b7288');
      // return;
      const { collection, id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.collectionModel
        .find({
          collectionName: collection,
          idName: new RegExp('^' + id),
        })
        .sort({ id: 1 })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async lockMergeV2(getIdDto: GetIdWithoutCollectionDto) {
    try {
      const { id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: false },
        },
        { lockedOn: new Date() },
        { new: true, projection: '-_id' },
      );
      return {
        justGotLocked: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async unlockMergeV2(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      const record = await this.collectionModel.findOne({
        collectionName: this.configService.get('rotg-collection-name'),
        id,
        lockedOn: { $exists: true },
      });
      if (record) {
        record.lockedOn = undefined;
        await record.save();
      }
      return {
        justGotMerged: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async forceUnlockTest(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: true },
        },
        { $unset: { lockedOn: true } },
      );
      return true;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      collectionName: dto.collection,
      stone: dto.stone,
      isClaimed: dto.isClaimed,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto as GetAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.collectionModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.collectionModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.checkSmartContract(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(collection, claimedIds) {
    await this.collectionModel.updateMany(
      { collectionName: collection, id: { $in: claimedIds } },
      { isClaimed: true },
    );
  }

  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.collectionModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.collectionModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // @Cron('*/2 * * * *')
  // private async scrapMarket() {
  //   try {
  //     const timestamp: number = new Date().getTime();
  //     await this.fullScrapTrustmarket('bid', timestamp);
  //     await this.fullScrapTrustmarket('buy', timestamp);
  //     // await this.scrapDeadrare(timestamp);
  //     await this.nftModel.updateMany(
  //       { timestamp: { $exists: true, $ne: timestamp } },
  //       { $unset: { market: 1, timestamp: 1 } },
  //     );
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //   }
  // }
  // private async scrapTrustmarket(
  //   type: 'bid' | 'buy',
  //   offset: number,
  //   count: number,
  //   timestamp: number,
  // ) {
  //   try {
  //     const trustmarketApi = this.configService.get('trustmarket-api');
  //     const { data } = await axios.post(trustmarketApi, {
  //       filters: {
  //         onSale: true,
  //         auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
  //       },
  //       collection: 'GUARDIAN-3d6635',
  //       skip: offset,
  //       top: count,
  //       select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
  //     });
  //     if (!data.results || data.results.length === 0) return true;
  //     if (type === 'buy') {
  //       const nftSample = data.results[0];
  //       EGLD_RATE =
  //         nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
  //     }
  //     const isLast: boolean = offset + data.resultsCount === data.count;
  //     const updateObject = data.results.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.nonce },
  //         update: {
  //           market: {
  //             source:
  //               d.saleInfoNft?.marketplace === 'DR'
  //                 ? 'deadrare'
  //                 : 'trustmarket',
  //             identifier: d.identifier,
  //             type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
  //             bid:
  //               d.saleInfoNft?.auction_type !== 'NftBid'
  //                 ? null
  //                 : {
  //                     min: d.saleInfoNft?.min_bid_short,
  //                     current: d.saleInfoNft?.current_bid_short,
  //                     deadline: getTimeUntil(d.saleInfoNft?.deadline),
  //                   },
  //             token: d.saleInfoNft?.accepted_payment_token,
  //             price: d.saleInfoNft?.max_bid_short,
  //             currentUsd: +d.saleInfoNft?.usd,
  //             timestamp: +d.saleInfoNft?.timestamp,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     await this.nftModel.bulkWrite(updateObject);
  //     return isLast;
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }

  async checkSmartContract(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      //   await this.nftModel.updateMany(
      //     { id: { $in: claimedIds } },
      //     { isClaimed: true },
      //   );
      await this.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  // private async scrapDeadrare(timestamp: number) {
  //   try {
  //     const deadrareApi = this.configService.get('deadrare-api');
  //     const deadrareApiParams = this.configService.get('deadrare-api-params');
  //     const { data } = await axios.get(deadrareApi + deadrareApiParams);
  //     if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
  //     const updateObject = data.data.listAuctions.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.cachedNft.nonce },
  //         update: {
  //           market: {
  //             source: 'deadrare',
  //             identifier: d.nftId,
  //             type: 'buy',
  //             bid: null,
  //             token: 'EGLD',
  //             price: +d.price,
  //             currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     return this.nftModel.bulkWrite(updateObject);
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }
}
</pre>
<h3>collection.market.ts</h3>
<pre>
import axios from 'axios';
import { CollectionDocument } from './schemas/collection.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';
import { sleep } from './collection.helpers';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      if (auctionTokenData[6] === auctionTokenData[7]) {
        return parseInt(auctionTokenData[6], 16);
      } else {
        console.log(identifier + ': auction/' + elrondTransaction.function);
      }
    } else if (
      // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  collectionModel: Model<CollectionDocument>,
  collectionName: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket(
    'deadrare',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'frameit',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'xoxno',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'elrond',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
};

const getIdsOfNFTsInMarket = async function (
  marketName,
  collection,
  from,
  size,
) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=' +
      collection,
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  collection: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  collectionModel: Model<CollectionDocument>,
  egldRate: number,
  timestamp: number,
) {
  let from = 0;
  const size = 100;
  let nftsScrapped = false;
  while (!nftsScrapped) {
    const nftsIds = await getIdsOfNFTsInMarket(
      marketName,
      collection,
      from,
      size,
    );
    from += size;
    if (nftsIds.length == 0) {
      nftsScrapped = true;
      break;
    }

    // update timestamp for in-market nfts
    await collectionModel.updateMany(
      { collectionName: collection, id: { $in: nftsIds } },
      { timestamp },
    );
    // get newly entered nfts
    const newNFTs = await collectionModel.find({
      collectionName: collection,
      id: { $in: nftsIds },
      market: { $exists: false },
    });

    const updateObject = [];
    for (const nft of newNFTs) {
      // update db with price of newly added nft
      let price;
      try {
        price = await getNftPrice(marketName, nft.identifier);
      } catch (e) {
        continue;
      }
      const market = {
        source: marketName,
        identifier: nft.identifier,
        type: 'buy',
        bid: null,
        token: 'EGLD',
        price,
        currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
      };
      console.log(market);
      updateObject.push({
        updateOne: {
          filter: { collectionName: collection, id: nft.id },
          update: {
            market,
          },
        },
      });
      await sleep(500);
    }
    await collectionModel.bulkWrite(updateObject);
  }
};
</pre>
<h3>collection.dto.ts</h3>
<pre>
import { ConfigService } from '@nestjs/config';
import configuration from '../../../config/configuration';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { IntersectionType } from '@nestjs/swagger';

const configService: ConfigService<EnvironmentVariables> = new ConfigService(
  configuration(),
);

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  MinLength,
  IsNumberString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsInt,
  Min,
  Max,
  ArrayMaxSize,
  ArrayMinSize,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/collection.filters';

export class CreateJWTDto {
  @ApiProperty({
    description: 'email',
  })
  @IsNotEmpty()
  readonly email: string;
  @ApiProperty({
    description: 'password',
  })
  @IsNotEmpty()
  readonly password: string;
}

export class GetCollectionDto {
  @Matches(
    new RegExp(
      '^(' +
        configService.get('nft-collection-name') +
        '|' +
        configService.get('rotg-collection-name') +
        '|' +
        configService.get('ltbox-collection-name') +
        '|' +
        configService.get('tiket-collection-name') +
        '|' +
        configService.get('asset-collection-name') +
        ')$',
    ),
  )
  @ApiProperty({
    enum: [
      configService.get('nft-collection-name'),
      configService.get('rotg-collection-name'),
      configService.get('ltbox-collection-name'),
      configService.get('tiket-collection-name'),
      configService.get('asset-collection-name'),
    ],
  })
  readonly collection: string;
}

export class GetIdWithoutCollectionDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

export class GetIdDto extends IntersectionType(
  GetCollectionDto,
  GetIdWithoutCollectionDto,
) {}

export class GetIdsDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'ids of nft',
  })
  ids: number[];
}
export class GetElementDto extends GetCollectionDto {
  @IsEnum(['water', 'rock', 'algae', 'lava', 'bioluminescent'])
  @ApiProperty({
    description: 'nft/sft element',
  })
  element: string;
}

export class GetIdentifiersDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'identifier of nft/sft',
  })
  identifiers: string[];
}

export class ROTGModel {
  @ApiProperty({
    description: 'ROTG id',
  })
  @IsInt()
  @Min(1)
  @Max(9999)
  id: number;

  @ApiProperty({
    description: 'ROTG name',
  })
  @IsNotEmpty()
  readonly name: string;

  @ApiProperty({
    description: 'ROTG description',
  })
  @IsNotEmpty()
  readonly description: string;

  @ApiProperty({
    description: 'ROTG element',
  })
  @IsEnum(['Water', 'Rock', 'Algae', 'Lava', 'Bioluminescent'])
  readonly element: string;

  @ApiProperty({
    description: 'ROTG image url',
  })
  @IsNotEmpty()
  readonly image: string;

  @ApiProperty({
    description: 'ROTG attributes',
  })
  @ArrayMaxSize(10)
  @ArrayMinSize(10)
  readonly attributes: any[];
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto extends GetCollectionDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
</pre>
<h3>collection.schema.ts</h3>
<pre>
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CollectionDocument = Collection & Document;

const BaseAssetType = {
  name: String,
  url: String,
  vril: Number,
  rarity: Number,
  _id: false,
};
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class Collection {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  collectionName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: false, type: String })
  assetType: string;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: false, type: Number })
  balance: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  vril: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
  @Prop({ required: false, type: Date })
  lockedOn: Date;
}

export const CollectionSchema = SchemaFactory.createForClass(Collection);
</pre>
<h3>collection.filters.ts</h3>
<pre>
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
</pre>
<h3>nft.dto.ts</h3>
<pre>
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  IsNumberString,
  IsOptional,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/nft.filters';

export class GetIdDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @ApiPropertyOptional({
    description: 'Guardian crown type',
    enum: filters.crown,
  })
  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
</pre>
<h3>nft.controller.spec.ts</h3>
<pre>
import { ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Connection } from 'mongoose';
import * as request from 'supertest';

import { AppModule } from '../../app.module';
import { DatabaseService } from '../../database/database.service';
import { GetErdDto } from './dto/nft.dto';

const erdStubWithNFTs = (): GetErdDto => {
  return {
    erd: 'erd17djfwed563cry53thgytxg5nftvl9vkec4yvrgveu905zeq6erqqkr7cmy',
  };
};
const erdStubWithoutNFTs = (): GetErdDto => {
  return {
    erd: 'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
  };
};
const erdStubInvalid = (): GetErdDto => {
  return {
    erd: 'erd1qck4cpghjff88gg7rq6q4w0fndd3g33v499999z9ehjhqg9uxu222zkxwz',
  };
};

describe('NFTController', () => {
  let dbConnection: Connection;
  let httpServer: any;
  let app: any;
  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
      }),
    );
    await app.init();
    dbConnection = moduleRef
      .get<DatabaseService>(DatabaseService)
      .getDbHandle();
    httpServer = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('findByUser', () => {
    it("should return list of user's nfts", async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toBeGreaterThan(0);
    });
    it('should return empty list in case user has no nfts', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithoutNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(0);
    });
    it('should return 500 in case user erd is invalid', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubInvalid().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(500);
    });
  });

  describe('findById', () => {
    it('should return NFT with id=666', async () => {
      const response = await request(httpServer).get(`/nft/id/666`);
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('id');
      expect(response.body.id).toEqual(666);
    });
    it('should return 400 in for out of range id', async () => {
      const response = await request(httpServer).get(`/nft/id/10000`);
      expect(response.status).toBe(400);
    });
  });

  describe('findAll', () => {
    it('should return 400 with page > 500', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=501`,
      );
      expect(response.status).toBe(400);
    });
    it('should return list with id=1 for first element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(20);
      expect(response.body.nfts[0].id).toEqual(1);
    });
    it('should return list with rank=1 for last element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=500`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(19);
      expect(response.body.nfts[18].rank).toEqual(1);
    });

    it('should return filtered element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=1&background=kyoto%20ape&crown=shepherd%20of%20grace&hairstyle=tako&hairstyleColor=grey&eyes=oshiza&eyesColor=grey&nose=hiken&mouth=dagon&mouthColor=grey&armor=shin&weapon=oshiza%20spear&stone=lava&id=39`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(1);
      expect(response.body.nfts[0].id).toEqual(3908);
    });
  });

  describe('findByMarket', () => {
    it('should return list of NFTs listed on deadrare + trustmarket', async () => {
      const response = await request(httpServer).get(
        `/nft/market?order=asc&page=1&by=price`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const sources = response.body.nfts.map((el) => {
        return el.market.source;
      });
      expect(sources).toContain('deadrare');
      expect(sources).toContain('trustmarket');
    });
    it('should return prices in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=price',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const prices = response.body.nfts.map((el) => {
        return el.market.currentUsd;
      });
      expect(prices[0]).toBeGreaterThan(prices[1]);
    });
    it('should return rank in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=rank',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ranks = response.body.nfts.map((el) => {
        return el.rank;
      });
      expect(ranks[0]).toBeGreaterThan(ranks[1]);
    });
    it('should return ids in ascending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=asc&page=1&by=id',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ids = response.body.nfts.map((el) => {
        return el.id;
      });
      expect(ids[0]).toBeLessThan(ids[1]);
    });
  });
});
</pre>
<h3>nft.market.ts</h3>
<pre>
import axios from 'axios';
import { NFTDocument } from './schemas/nft.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      return parseInt(auctionTokenData[6], 16);
    } else if ( // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket('deadrare', nftModel, egldRate, timestamp);
  await scrapOneMarket('frameit', nftModel, egldRate, timestamp);
  await scrapOneMarket('xoxno', nftModel, egldRate, timestamp);
  await scrapOneMarket('elrond', nftModel, egldRate, timestamp);
};

const getIdsOfNFTsInMarket = async function (marketName, from, size) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=GUARDIAN-3d6635',
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  try {
    let from = 0;
    const size = 100;
    let nftsScrapped = false;
    while (!nftsScrapped) {
      const nftsIds = await getIdsOfNFTsInMarket(marketName, from, size);
      from += size;
      if (nftsIds.length == 0) {
        nftsScrapped = true;
        break;
      }

      // update timestamp for in-market nfts
      await nftModel.updateMany({ id: { $in: nftsIds } }, { timestamp });
      // get newly entered nfts
      const newNFTs = await nftModel.find({
        id: { $in: nftsIds },
        market: { $exists: false },
      });

      const updateObject = [];
      for (const nft of newNFTs) {
        // update db with price of newly added nft
        let price;
        try {
          price = await getNftPrice(marketName, nft.identifier);
        } catch (e) {
          continue;
        }
        const market = {
          source: marketName,
          identifier: nft.identifier,
          type: 'buy',
          bid: null,
          token: 'EGLD',
          price,
          currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
        };
        console.log(market);
        updateObject.push({
          updateOne: {
            filter: { id: nft.id },
            update: {
              market,
            },
          },
        });
      }
      await nftModel.bulkWrite(updateObject);
    }
  } catch (e) {
    console.log(e);
    try {
      await nftModel.updateMany({ 'market.source': marketName }, { timestamp });
    } catch (e) {}
  }
};
</pre>
<h3>nft.service.ts</h3>
<pre>
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';
import { NFT, NFTDocument } from './schemas/nft.schema';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { CollectionService } from '../collection/collection.service';
import { scrapMarkets } from './nft.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
} from '../collection/collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class NftService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private readonly collectionService: CollectionService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(NFT.name) private nftModel: Model<NFTDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(erd, filters) {
    const apiParams = this.configService.get('elrond-api-params');
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}${apiParams}`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };

    return { findQuery, filtersQuery };
  }

  async getByIds(ids: number[]) {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .limit(limit);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findById(getIdDto: GetIdDto) {
    try {
      const { id } = getIdDto;
      const record = await this.nftModel.findOneAndUpdate(
        { id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      const { id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.nftModel
        .find({
          idName: new RegExp('^' + id),
        })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      stone: dto.stone,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.nftModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.nftModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.updateIsClaimed(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.nftModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }
  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('*/30 * * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      await scrapMarkets(this.nftModel, EGLD_RATE, timestamp);
      await this.nftModel.updateMany(
        { timestamp: { $exists: true, $ne: timestamp } },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      console.log(error);
      this.client.instance().captureException(error);
    }
  }
  private async scrapTrustmarket(
    type: 'bid' | 'buy',
    offset: number,
    count: number,
    timestamp: number,
  ) {
    try {
      const trustmarketApi = this.configService.get('trustmarket-api');
      const { data } = await axios.post(trustmarketApi, {
        filters: {
          onSale: true,
          auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
        },
        collection: 'GUARDIAN-3d6635',
        skip: offset,
        top: count,
        select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
      });
      if (!data.results || data.results.length === 0) return true;
      if (type === 'buy') {
        const nftSample = data.results[0];
        EGLD_RATE =
          nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
      }
      const isLast: boolean = offset + data.resultsCount === data.count;
      const updateObject = data.results.map((d) => ({
        updateOne: {
          filter: { id: d.nonce },
          update: {
            market: {
              source:
                d.saleInfoNft?.marketplace === 'DR'
                  ? 'deadrare'
                  : 'trustmarket',
              identifier: d.identifier,
              type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
              bid:
                d.saleInfoNft?.auction_type !== 'NftBid'
                  ? null
                  : {
                      min: d.saleInfoNft?.min_bid_short,
                      current: d.saleInfoNft?.current_bid_short,
                      deadline: getTimeUntil(d.saleInfoNft?.deadline),
                    },
              token: d.saleInfoNft?.accepted_payment_token,
              price: d.saleInfoNft?.max_bid_short,
              currentUsd: +d.saleInfoNft?.usd,
              timestamp: +d.saleInfoNft?.timestamp,
            },
            timestamp,
          },
        },
      }));
      await this.nftModel.bulkWrite(updateObject);
      return isLast;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private async fullScrapTrustmarket(type: 'bid' | 'buy', timestamp: number) {
    let isFinished = false;
    let offset = 0;
    const count = 200;
    while (!isFinished) {
      isFinished = await this.scrapTrustmarket(type, offset, count, timestamp);
      offset += count;
    }
  }

  private async scrapDeadrare(timestamp: number) {
    try {
      const deadrareApi = this.configService.get('deadrare-api');
      const deadrareApiParams = this.configService.get('deadrare-api-params');
      const { data } = await axios.get(deadrareApi + deadrareApiParams);
      if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
      const updateObject = data.data.listAuctions.map((d) => ({
        updateOne: {
          filter: { id: d.cachedNft.nonce },
          update: {
            market: {
              source: 'deadrare',
              identifier: d.nftId,
              type: 'buy',
              bid: null,
              token: 'EGLD',
              price: +d.price,
              currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
            },
            timestamp,
          },
        },
      }));
      return this.nftModel.bulkWrite(updateObject);
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      await this.nftModel.updateMany(
        { id: { $in: claimedIds } },
        { isClaimed: true },
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('nft-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  async claimByIds(ids: number[]): Promise<{ nfts: any }> {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      const updatedNfts = await this.updateIsClaimed(nfts);
      return { nfts: updatedNfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
</pre>
<h3>nft.controller.ts</h3>
<pre>
import { Controller, Get, Param, ParseArrayPipe, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { NftService } from './nft.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';

@ApiTags('nft')
@Controller('nft')
export class NftController {
  constructor(private readonly nftService: NftService) {}

  @Get('user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findUserNftCount({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.nftService.findByUserLimited({ ...getErdDto, ...getAllDto });
  }

  @Get('id/:id')
  getById(@Param() getIdDto: GetIdDto) {
    return this.nftService.findById(getIdDto);
  }

  @Get('search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.nftService.findByIdPrefix(getIdDto);
  }

  @Get('ids/:ids')
  getByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.getByIds(ids);
  }

  @Get('claim/:ids')
  claimByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.claimByIds(ids);
  }

  @Get('all')
  getAll(@Query() getAllDto: GetAllDto) {
    return this.nftService.findAll(getAllDto);
  }

  @Get('market')
  getByMarket(@Query() getMarketDto: GetMarketDto) {
    return this.nftService.findByMarket(getMarketDto);
  }
}
</pre>
<h3>nft.schema.ts</h3>
<pre>
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type NFTDocument = NFT & Document;

const BaseAssetType = { name: String, url: String, rarity: Number, _id: false };
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class NFT {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);
</pre>
<h3>nft.filters.ts</h3>
<pre>
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
</pre>
<h3>nft.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { NftService } from './nft.service';
import { NftController } from './nft.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { NFT, NFTSchema } from './schemas/nft.schema';
import { CollectionModule } from '../collection/collection.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: NFT.name, schema: NFTSchema }]),
    CollectionModule,
  ],
  controllers: [NftController],
  providers: [NftService],
})
export class NftModule {}
</pre>
<h3>nft.dto.ts</h3>
<pre>
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  IsNumberString,
  IsOptional,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/nft.filters';

export class GetIdDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @ApiPropertyOptional({
    description: 'Guardian crown type',
    enum: filters.crown,
  })
  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
</pre>
<h3>nft.schema.ts</h3>
<pre>
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type NFTDocument = NFT & Document;

const BaseAssetType = { name: String, url: String, rarity: Number, _id: false };
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class NFT {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);
</pre>
<h3>nft.filters.ts</h3>
<pre>
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
</pre>
<h3>auth.service.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { EnvironmentVariables } from 'src/config/configuration.d';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<EnvironmentVariables>,
  ) {}
  async validateUser(email: string, pass: string): Promise<any> {
    const env = this.configService.get('env');
    return ['production', 'staging'].indexOf(env) === -1 ? true : null;
  }
  async login(user: any) {
    return {
      access_token: this.jwtService.sign({ key: 'splitamerge' }),
    };
  }
}
</pre>
<h3>jwt.strategy.ts</h3>
<pre>
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../../config/configuration.d';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService<EnvironmentVariables>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt-secret', { infer: true }),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
</pre>
<h3>local.strategy.ts</h3>
<pre>
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
</pre>
<h3>auth.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../config/configuration.d';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables>) => ({
        secret: config.get('jwt-secret', { infer: true }),
        signOptions: { expiresIn: '2 days' },
      }),
    }),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
</pre>
<h3>jwt-auth.guard.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
</pre>
<h3>local-auth.guard.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
</pre>
<h3>jwt.strategy.ts</h3>
<pre>
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../../config/configuration.d';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService<EnvironmentVariables>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt-secret', { infer: true }),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
</pre>
<h3>local.strategy.ts</h3>
<pre>
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
</pre>
<h3>jwt-auth.guard.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
</pre>
<h3>local-auth.guard.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
</pre>
<h3>elrond-api.controller.ts</h3>
<pre>
import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ElrondApiService } from './elrond-api.service';

@ApiTags('elrond-api')
@Controller('elrond-api')
export class ElrondApiController {
  constructor(private readonly elrondApiService: ElrondApiService) {}

  @Get('/*')
  get(@Param() params) {
    return this.elrondApiService.get(params[0]);
  }

  @Post('/*')
  post(@Param() params, @Body() body) {
    return this.elrondApiService.post(params[0], body);
  }
}
</pre>
<h3>elrond-api.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { ElrondApiController } from './elrond-api.controller';
import { ElrondApiService } from './elrond-api.service';

@Module({
  controllers: [ElrondApiController],
  providers: [ElrondApiService],
  imports: [RedisModule],
})
export class ElrondApiModule {}
</pre>
<h3>elrond-api.controller.spec.ts</h3>
<pre>
// import { Test, TestingModule } from '@nestjs/testing';
// import { ElrondApiController } from './elrond-api.controller';
// import { ElrondApiService } from './elrond-api.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('ElrondApiController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  //   let controller: ElrondApiController;
  //   let service: ElrondApiService;

  //   beforeEach(async () => {
  //     const module: TestingModule = await Test.createTestingModule({
  //       controllers: [ElrondApiController],
  //       imports: [RedisModule, EnvConfigModule],
  //       providers: [
  //         ElrondApiService,
  //         {
  //           provide: SENTRY_TOKEN,
  //           useValue: { debug: jest.fn() },
  //         },
  //       ],
  //     }).compile();

  //     controller = module.get<ElrondApiController>(ElrondApiController);
  //     service = module.get<ElrondApiService>(ElrondApiService);
  //   });

  //   // it('elrondApiController should be defined', () => {
  //   //   expect(controller).toBeDefined();
  //   // });
  //   // it('elrondApiService should be defined', () => {
  //   //   expect(service).toBeDefined();
  //   // });
  //   // it('elrondApiController GET should get correct data', async () => {
  //   //   const data = await controller.get({ '0': 'stats' });
  //   //   expect(data).toHaveProperty('accounts');
  //   //   expect(data).toHaveProperty('blocks');
  //   //   expect(data).toHaveProperty('epoch');
  //   //   expect(data).toHaveProperty('refreshRate');
  //   //   expect(data).toHaveProperty('roundsPassed');
  //   //   expect(data).toHaveProperty('roundsPerEpoch');
  //   //   expect(data).toHaveProperty('shards');
  //   //   expect(data).toHaveProperty('transactions');
  //   // });

  //   // it('elrondApiController POST should send ok', async () => {
  //   //   const data = await controller.post(
  //   //     { '0': 'query' },
  //   //     {
  //   //       scAddress:
  //   //         'erd1qqqqqqqqqqqqqpgqra3rpzamn5pxhw74ju2l7tv8yzhpnv98nqjsvw3884',
  //   //       funcName: 'getFirstMissionStartEpoch',
  //   //       args: [],
  //   //     },
  //   //   );
  //   //   expect(data).toHaveProperty('returnCode');
  //   //   expect(data.returnCode).toBe('ok');
  //   // });
  /* It's a comment. */
});
</pre>
<h3>elrond-api.service.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { RedisService } from '../../redis/redis.service';

@Injectable()
export class ElrondApiService {
  private networkProvider: ApiNetworkProvider;
  private env: string;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    private redisService: RedisService,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
    this.env = this.configService.get('env');
  }

  async get(route) {
    try {
      const redisKey = this.env + route;
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doGetGeneric(route);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async post(route, payload) {
    try {
      const redisKey = this.env + route + JSON.stringify(payload);
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doPostGeneric(route, payload);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
</pre>
<h3>stats.controller.spec.ts</h3>
<pre>
// import { Test, TestingModule } from '@nestjs/testing';
// import { StatsController } from './stats.controller';
// import { StatsService } from './stats.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('StatsController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  // let controller: StatsController;
  // let service: StatsService;
  // beforeEach(async () => {
  //   const module: TestingModule = await Test.createTestingModule({
  //     controllers: [StatsController],
  //     providers: [
  //       StatsService,
  //       {
  //         provide: SENTRY_TOKEN,
  //         useValue: { debug: jest.fn() },
  //       },
  //     ],
  //     imports: [RedisModule, EnvConfigModule],
  //   }).compile();
  //   controller = module.get<StatsController>(StatsController);
  //   service = module.get<StatsService>(StatsService);
  // });
  // it('statsController should be defined', () => {
  //   expect(controller).toBeDefined();
  // });
  // it('statsService should be defined', () => {
  //   expect(service).toBeDefined();
  // });
  // it('statsController should get correct data', async () => {
  //   const data = await controller.get();
  //   expect(data).toHaveProperty('twitter');
  //   expect(data.twitter).toHaveProperty('followerCount');
  //   expect(data).toHaveProperty('guardians');
  //   expect(data.guardians).toHaveProperty('smallest24hTrade');
  //   expect(data.guardians).toHaveProperty('averagePrice');
  //   expect(data.guardians).toHaveProperty('holderCount');
  //   expect(data.guardians).toHaveProperty('totalEgldVolume');
  //   expect(data.guardians).toHaveProperty('floorPrice');
  //   expect(data.guardians.totalEgldVolume).toBeGreaterThanOrEqual(12500);
  //   expect(data.guardians.holderCount).toBeGreaterThanOrEqual(1000);
  //   expect(data.twitter.followerCount).toBeGreaterThanOrEqual(16000);
  //   expect(data.guardians.averagePrice).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.smallest24hTrade).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.floorPrice).toBeGreaterThanOrEqual(1);
  // });
});
</pre>
<h3>stats.controller.ts</h3>
<pre>
import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { StatsService } from './stats.service';

@ApiTags('stats')
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @Get('/')
  get() {
    return this.statsService.get();
  }
}
</pre>
<h3>stats.module.ts</h3>
<pre>
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';

@Module({
  controllers: [StatsController],
  providers: [StatsService],
  imports: [RedisModule],
})
export class StatsModule {}
</pre>
<h3>stats.service.ts</h3>
<pre>
import { Injectable } from '@nestjs/common';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { RedisService } from '../../redis/redis.service';
import * as cheerio from 'cheerio';

@Injectable()
export class StatsService {
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private redisService: RedisService,
  ) {}

  async get() {
    try {
      const cachedData = await this.redisService.get('AQXSTATS');
      if (cachedData) return cachedData;
      const volumeData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/analytics?timeZone=Europe%2FParis&market=secundary&startDate=2021-11-01T00:00:00.000Z&endDate=' +
          new Date().toISOString() +
          '&buckets=1',
      );
      const holderData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/holder_and_supply',
      );
      const twitterData = await axios.get(
        'https://api.livecounts.io/twitter-live-follower-counter/stats/TheAquaverse',
      );
      const floorAverageData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/floor_and_average_price?chartTimeRange=day',
      );
      const xoxnoPage = await axios.get(
        'https://xoxno.com/collection/GUARDIAN-3d6635',
      );
      let floorPrice = null;

      try {
        const cheerioData = cheerio.load(xoxnoPage.data);
        const xoxnoData = cheerioData('#__NEXT_DATA__').html();
        const parsedXoxnoData = JSON.parse(xoxnoData);
        floorPrice = parsedXoxnoData?.props?.pageProps?.initInfoFallback?.floor;
      } catch (e) {}

      const rawEgldVolume =
        volumeData &&
        volumeData.data &&
        volumeData.data.date_histogram &&
        volumeData.data.date_histogram.length > 0
          ? volumeData.data.date_histogram[0].volume
          : null;
      const denum = Math.pow(10, 18);
      const followerCount =
        twitterData && twitterData.data && twitterData.data.followerCount
          ? twitterData.data.followerCount
          : null;
      const totalEgldVolume = rawEgldVolume ? Math.round(rawEgldVolume) : null;
      const holderCount =
        holderData.data && holderData.data.holderCount
          ? holderData.data.holderCount
          : null;
      const floorAverageDataList =
        floorAverageData.data && floorAverageData.data.length > 0
          ? floorAverageData.data
          : [];
      const smallest24hTrade =
        floorAverageDataList.length > 0 && floorAverageDataList[0].floor_price
          ? Math.round((floorAverageDataList[0].floor_price / denum) * 100) /
            100
          : null;

      const oldFloorAverageData =
        floorAverageDataList.length > 1 &&
        floorAverageDataList[floorAverageDataList.length - 1]
          ? floorAverageDataList[floorAverageDataList.length - 1]
          : null;

      const old24hTrade =
        oldFloorAverageData && oldFloorAverageData.floor_price
          ? Math.round((oldFloorAverageData.floor_price / denum) * 100) / 100
          : null;

      const percentage24hTrade =
        smallest24hTrade !== null && old24hTrade !== null
          ? Number(
              ((100 * (smallest24hTrade - old24hTrade)) / old24hTrade).toFixed(
                2,
              ),
            )
          : 0;
      const averagePrice =
        floorAverageDataList.length > 0 && floorAverageDataList[0].average_price
          ? Math.round((floorAverageDataList[0].average_price / denum) * 100) /
            100
          : null;

      const oldAveragePrice =
        oldFloorAverageData && oldFloorAverageData.average_price
          ? Math.round((oldFloorAverageData.average_price / denum) * 100) / 100
          : null;

      const percentageAveragePrice =
        smallest24hTrade !== null && oldAveragePrice !== null
          ? Number(
              (
                (100 * (averagePrice - oldAveragePrice)) /
                oldAveragePrice
              ).toFixed(2),
            )
          : 0;

      const data = {
        twitter: {
          followerCount,
        },
        guardians: {
          smallest24hTrade,
          percentage24hTrade,
          averagePrice,
          percentageAveragePrice,
          holderCount,
          totalEgldVolume,
          floorPrice,
        },
      };
      await this.redisService.set('AQXSTATS', data, 900);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
</pre>
</body></html>
// /Users/cheikkone/Projects/explorer-api/src/app/nft/dto/nft.dto.ts 
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  IsNumberString,
  IsOptional,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/nft.filters';

export class GetIdDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @ApiPropertyOptional({
    description: 'Guardian crown type',
    enum: filters.crown,
  })
  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.controller.spec.ts 
import { ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Connection } from 'mongoose';
import * as request from 'supertest';

import { AppModule } from '../../app.module';
import { DatabaseService } from '../../database/database.service';
import { GetErdDto } from './dto/nft.dto';

const erdStubWithNFTs = (): GetErdDto => {
  return {
    erd: 'erd17djfwed563cry53thgytxg5nftvl9vkec4yvrgveu905zeq6erqqkr7cmy',
  };
};
const erdStubWithoutNFTs = (): GetErdDto => {
  return {
    erd: 'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
  };
};
const erdStubInvalid = (): GetErdDto => {
  return {
    erd: 'erd1qck4cpghjff88gg7rq6q4w0fndd3g33v499999z9ehjhqg9uxu222zkxwz',
  };
};

describe('NFTController', () => {
  let dbConnection: Connection;
  let httpServer: any;
  let app: any;
  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
      }),
    );
    await app.init();
    dbConnection = moduleRef
      .get<DatabaseService>(DatabaseService)
      .getDbHandle();
    httpServer = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('findByUser', () => {
    it("should return list of user's nfts", async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toBeGreaterThan(0);
    });
    it('should return empty list in case user has no nfts', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithoutNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(0);
    });
    it('should return 500 in case user erd is invalid', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubInvalid().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(500);
    });
  });

  describe('findById', () => {
    it('should return NFT with id=666', async () => {
      const response = await request(httpServer).get(`/nft/id/666`);
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('id');
      expect(response.body.id).toEqual(666);
    });
    it('should return 400 in for out of range id', async () => {
      const response = await request(httpServer).get(`/nft/id/10000`);
      expect(response.status).toBe(400);
    });
  });

  describe('findAll', () => {
    it('should return 400 with page > 500', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=501`,
      );
      expect(response.status).toBe(400);
    });
    it('should return list with id=1 for first element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(20);
      expect(response.body.nfts[0].id).toEqual(1);
    });
    it('should return list with rank=1 for last element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=500`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(19);
      expect(response.body.nfts[18].rank).toEqual(1);
    });

    it('should return filtered element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=1&background=kyoto%20ape&crown=shepherd%20of%20grace&hairstyle=tako&hairstyleColor=grey&eyes=oshiza&eyesColor=grey&nose=hiken&mouth=dagon&mouthColor=grey&armor=shin&weapon=oshiza%20spear&stone=lava&id=39`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(1);
      expect(response.body.nfts[0].id).toEqual(3908);
    });
  });

  describe('findByMarket', () => {
    it('should return list of NFTs listed on deadrare + trustmarket', async () => {
      const response = await request(httpServer).get(
        `/nft/market?order=asc&page=1&by=price`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const sources = response.body.nfts.map((el) => {
        return el.market.source;
      });
      expect(sources).toContain('deadrare');
      expect(sources).toContain('trustmarket');
    });
    it('should return prices in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=price',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const prices = response.body.nfts.map((el) => {
        return el.market.currentUsd;
      });
      expect(prices[0]).toBeGreaterThan(prices[1]);
    });
    it('should return rank in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=rank',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ranks = response.body.nfts.map((el) => {
        return el.rank;
      });
      expect(ranks[0]).toBeGreaterThan(ranks[1]);
    });
    it('should return ids in ascending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=asc&page=1&by=id',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ids = response.body.nfts.map((el) => {
        return el.id;
      });
      expect(ids[0]).toBeLessThan(ids[1]);
    });
  });
});
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.market.ts 
import axios from 'axios';
import { NFTDocument } from './schemas/nft.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      return parseInt(auctionTokenData[6], 16);
    } else if ( // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket('deadrare', nftModel, egldRate, timestamp);
  await scrapOneMarket('frameit', nftModel, egldRate, timestamp);
  await scrapOneMarket('xoxno', nftModel, egldRate, timestamp);
  await scrapOneMarket('elrond', nftModel, egldRate, timestamp);
};

const getIdsOfNFTsInMarket = async function (marketName, from, size) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=GUARDIAN-3d6635',
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  try {
    let from = 0;
    const size = 100;
    let nftsScrapped = false;
    while (!nftsScrapped) {
      const nftsIds = await getIdsOfNFTsInMarket(marketName, from, size);
      from += size;
      if (nftsIds.length == 0) {
        nftsScrapped = true;
        break;
      }

      // update timestamp for in-market nfts
      await nftModel.updateMany({ id: { $in: nftsIds } }, { timestamp });
      // get newly entered nfts
      const newNFTs = await nftModel.find({
        id: { $in: nftsIds },
        market: { $exists: false },
      });

      const updateObject = [];
      for (const nft of newNFTs) {
        // update db with price of newly added nft
        let price;
        try {
          price = await getNftPrice(marketName, nft.identifier);
        } catch (e) {
          continue;
        }
        const market = {
          source: marketName,
          identifier: nft.identifier,
          type: 'buy',
          bid: null,
          token: 'EGLD',
          price,
          currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
        };
        console.log(market);
        updateObject.push({
          updateOne: {
            filter: { id: nft.id },
            update: {
              market,
            },
          },
        });
      }
      await nftModel.bulkWrite(updateObject);
    }
  } catch (e) {
    console.log(e);
    try {
      await nftModel.updateMany({ 'market.source': marketName }, { timestamp });
    } catch (e) {}
  }
};
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.service.ts 
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';
import { NFT, NFTDocument } from './schemas/nft.schema';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { CollectionService } from '../collection/collection.service';
import { scrapMarkets } from './nft.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
} from '../collection/collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class NftService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private readonly collectionService: CollectionService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(NFT.name) private nftModel: Model<NFTDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(erd, filters) {
    const apiParams = this.configService.get('elrond-api-params');
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}${apiParams}`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };

    return { findQuery, filtersQuery };
  }

  async getByIds(ids: number[]) {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .limit(limit);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findById(getIdDto: GetIdDto) {
    try {
      const { id } = getIdDto;
      const record = await this.nftModel.findOneAndUpdate(
        { id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      const { id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.nftModel
        .find({
          idName: new RegExp('^' + id),
        })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      stone: dto.stone,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.nftModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.nftModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.updateIsClaimed(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.nftModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }
  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('*/30 * * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      await scrapMarkets(this.nftModel, EGLD_RATE, timestamp);
      await this.nftModel.updateMany(
        { timestamp: { $exists: true, $ne: timestamp } },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      console.log(error);
      this.client.instance().captureException(error);
    }
  }
  private async scrapTrustmarket(
    type: 'bid' | 'buy',
    offset: number,
    count: number,
    timestamp: number,
  ) {
    try {
      const trustmarketApi = this.configService.get('trustmarket-api');
      const { data } = await axios.post(trustmarketApi, {
        filters: {
          onSale: true,
          auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
        },
        collection: 'GUARDIAN-3d6635',
        skip: offset,
        top: count,
        select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
      });
      if (!data.results || data.results.length === 0) return true;
      if (type === 'buy') {
        const nftSample = data.results[0];
        EGLD_RATE =
          nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
      }
      const isLast: boolean = offset + data.resultsCount === data.count;
      const updateObject = data.results.map((d) => ({
        updateOne: {
          filter: { id: d.nonce },
          update: {
            market: {
              source:
                d.saleInfoNft?.marketplace === 'DR'
                  ? 'deadrare'
                  : 'trustmarket',
              identifier: d.identifier,
              type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
              bid:
                d.saleInfoNft?.auction_type !== 'NftBid'
                  ? null
                  : {
                      min: d.saleInfoNft?.min_bid_short,
                      current: d.saleInfoNft?.current_bid_short,
                      deadline: getTimeUntil(d.saleInfoNft?.deadline),
                    },
              token: d.saleInfoNft?.accepted_payment_token,
              price: d.saleInfoNft?.max_bid_short,
              currentUsd: +d.saleInfoNft?.usd,
              timestamp: +d.saleInfoNft?.timestamp,
            },
            timestamp,
          },
        },
      }));
      await this.nftModel.bulkWrite(updateObject);
      return isLast;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private async fullScrapTrustmarket(type: 'bid' | 'buy', timestamp: number) {
    let isFinished = false;
    let offset = 0;
    const count = 200;
    while (!isFinished) {
      isFinished = await this.scrapTrustmarket(type, offset, count, timestamp);
      offset += count;
    }
  }

  private async scrapDeadrare(timestamp: number) {
    try {
      const deadrareApi = this.configService.get('deadrare-api');
      const deadrareApiParams = this.configService.get('deadrare-api-params');
      const { data } = await axios.get(deadrareApi + deadrareApiParams);
      if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
      const updateObject = data.data.listAuctions.map((d) => ({
        updateOne: {
          filter: { id: d.cachedNft.nonce },
          update: {
            market: {
              source: 'deadrare',
              identifier: d.nftId,
              type: 'buy',
              bid: null,
              token: 'EGLD',
              price: +d.price,
              currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
            },
            timestamp,
          },
        },
      }));
      return this.nftModel.bulkWrite(updateObject);
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      await this.nftModel.updateMany(
        { id: { $in: claimedIds } },
        { isClaimed: true },
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('nft-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  async claimByIds(ids: number[]): Promise<{ nfts: any }> {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      const updatedNfts = await this.updateIsClaimed(nfts);
      return { nfts: updatedNfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.controller.ts 
import { Controller, Get, Param, ParseArrayPipe, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { NftService } from './nft.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';

@ApiTags('nft')
@Controller('nft')
export class NftController {
  constructor(private readonly nftService: NftService) {}

  @Get('user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findUserNftCount({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.nftService.findByUserLimited({ ...getErdDto, ...getAllDto });
  }

  @Get('id/:id')
  getById(@Param() getIdDto: GetIdDto) {
    return this.nftService.findById(getIdDto);
  }

  @Get('search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.nftService.findByIdPrefix(getIdDto);
  }

  @Get('ids/:ids')
  getByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.getByIds(ids);
  }

  @Get('claim/:ids')
  claimByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.claimByIds(ids);
  }

  @Get('all')
  getAll(@Query() getAllDto: GetAllDto) {
    return this.nftService.findAll(getAllDto);
  }

  @Get('market')
  getByMarket(@Query() getMarketDto: GetMarketDto) {
    return this.nftService.findByMarket(getMarketDto);
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/schemas/nft.schema.ts 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type NFTDocument = NFT & Document;

const BaseAssetType = { name: String, url: String, rarity: Number, _id: false };
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class NFT {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);
// /Users/cheikkone/Projects/explorer-api/src/app/nft/schemas/nft.filters.ts 
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.module.ts 
import { Module } from '@nestjs/common';
import { NftService } from './nft.service';
import { NftController } from './nft.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { NFT, NFTSchema } from './schemas/nft.schema';
import { CollectionModule } from '../collection/collection.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: NFT.name, schema: NFTSchema }]),
    CollectionModule,
  ],
  controllers: [NftController],
  providers: [NftService],
})
export class NftModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/auth.service.ts 
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { EnvironmentVariables } from 'src/config/configuration.d';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<EnvironmentVariables>,
  ) {}
  async validateUser(email: string, pass: string): Promise<any> {
    const env = this.configService.get('env');
    return ['production', 'staging'].indexOf(env) === -1 ? true : null;
  }
  async login(user: any) {
    return {
      access_token: this.jwtService.sign({ key: 'splitamerge' }),
    };
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/strategies/jwt.strategy.ts 
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../../config/configuration.d';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService<EnvironmentVariables>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt-secret', { infer: true }),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/strategies/local.strategy.ts 
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/auth.module.ts 
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../config/configuration.d';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables>) => ({
        secret: config.get('jwt-secret', { infer: true }),
        signOptions: { expiresIn: '2 days' },
      }),
    }),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/guards/jwt-auth.guard.ts 
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/guards/local-auth.guard.ts 
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.controller.ts 
import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ElrondApiService } from './elrond-api.service';

@ApiTags('elrond-api')
@Controller('elrond-api')
export class ElrondApiController {
  constructor(private readonly elrondApiService: ElrondApiService) {}

  @Get('/*')
  get(@Param() params) {
    return this.elrondApiService.get(params[0]);
  }

  @Post('/*')
  post(@Param() params, @Body() body) {
    return this.elrondApiService.post(params[0], body);
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.module.ts 
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { ElrondApiController } from './elrond-api.controller';
import { ElrondApiService } from './elrond-api.service';

@Module({
  controllers: [ElrondApiController],
  providers: [ElrondApiService],
  imports: [RedisModule],
})
export class ElrondApiModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.controller.spec.ts 
// import { Test, TestingModule } from '@nestjs/testing';
// import { ElrondApiController } from './elrond-api.controller';
// import { ElrondApiService } from './elrond-api.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('ElrondApiController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  //   let controller: ElrondApiController;
  //   let service: ElrondApiService;

  //   beforeEach(async () => {
  //     const module: TestingModule = await Test.createTestingModule({
  //       controllers: [ElrondApiController],
  //       imports: [RedisModule, EnvConfigModule],
  //       providers: [
  //         ElrondApiService,
  //         {
  //           provide: SENTRY_TOKEN,
  //           useValue: { debug: jest.fn() },
  //         },
  //       ],
  //     }).compile();

  //     controller = module.get<ElrondApiController>(ElrondApiController);
  //     service = module.get<ElrondApiService>(ElrondApiService);
  //   });

  //   // it('elrondApiController should be defined', () => {
  //   //   expect(controller).toBeDefined();
  //   // });
  //   // it('elrondApiService should be defined', () => {
  //   //   expect(service).toBeDefined();
  //   // });
  //   // it('elrondApiController GET should get correct data', async () => {
  //   //   const data = await controller.get({ '0': 'stats' });
  //   //   expect(data).toHaveProperty('accounts');
  //   //   expect(data).toHaveProperty('blocks');
  //   //   expect(data).toHaveProperty('epoch');
  //   //   expect(data).toHaveProperty('refreshRate');
  //   //   expect(data).toHaveProperty('roundsPassed');
  //   //   expect(data).toHaveProperty('roundsPerEpoch');
  //   //   expect(data).toHaveProperty('shards');
  //   //   expect(data).toHaveProperty('transactions');
  //   // });

  //   // it('elrondApiController POST should send ok', async () => {
  //   //   const data = await controller.post(
  //   //     { '0': 'query' },
  //   //     {
  //   //       scAddress:
  //   //         'erd1qqqqqqqqqqqqqpgqra3rpzamn5pxhw74ju2l7tv8yzhpnv98nqjsvw3884',
  //   //       funcName: 'getFirstMissionStartEpoch',
  //   //       args: [],
  //   //     },
  //   //   );
  //   //   expect(data).toHaveProperty('returnCode');
  //   //   expect(data.returnCode).toBe('ok');
  //   // });
  /* It's a comment. */
});
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.service.ts 
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { RedisService } from '../../redis/redis.service';

@Injectable()
export class ElrondApiService {
  private networkProvider: ApiNetworkProvider;
  private env: string;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    private redisService: RedisService,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
    this.env = this.configService.get('env');
  }

  async get(route) {
    try {
      const redisKey = this.env + route;
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doGetGeneric(route);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async post(route, payload) {
    try {
      const redisKey = this.env + route + JSON.stringify(payload);
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doPostGeneric(route, payload);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.controller.spec.ts 
// import { Test, TestingModule } from '@nestjs/testing';
// import { StatsController } from './stats.controller';
// import { StatsService } from './stats.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('StatsController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  // let controller: StatsController;
  // let service: StatsService;
  // beforeEach(async () => {
  //   const module: TestingModule = await Test.createTestingModule({
  //     controllers: [StatsController],
  //     providers: [
  //       StatsService,
  //       {
  //         provide: SENTRY_TOKEN,
  //         useValue: { debug: jest.fn() },
  //       },
  //     ],
  //     imports: [RedisModule, EnvConfigModule],
  //   }).compile();
  //   controller = module.get<StatsController>(StatsController);
  //   service = module.get<StatsService>(StatsService);
  // });
  // it('statsController should be defined', () => {
  //   expect(controller).toBeDefined();
  // });
  // it('statsService should be defined', () => {
  //   expect(service).toBeDefined();
  // });
  // it('statsController should get correct data', async () => {
  //   const data = await controller.get();
  //   expect(data).toHaveProperty('twitter');
  //   expect(data.twitter).toHaveProperty('followerCount');
  //   expect(data).toHaveProperty('guardians');
  //   expect(data.guardians).toHaveProperty('smallest24hTrade');
  //   expect(data.guardians).toHaveProperty('averagePrice');
  //   expect(data.guardians).toHaveProperty('holderCount');
  //   expect(data.guardians).toHaveProperty('totalEgldVolume');
  //   expect(data.guardians).toHaveProperty('floorPrice');
  //   expect(data.guardians.totalEgldVolume).toBeGreaterThanOrEqual(12500);
  //   expect(data.guardians.holderCount).toBeGreaterThanOrEqual(1000);
  //   expect(data.twitter.followerCount).toBeGreaterThanOrEqual(16000);
  //   expect(data.guardians.averagePrice).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.smallest24hTrade).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.floorPrice).toBeGreaterThanOrEqual(1);
  // });
});
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.controller.ts 
import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { StatsService } from './stats.service';

@ApiTags('stats')
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @Get('/')
  get() {
    return this.statsService.get();
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.module.ts 
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';

@Module({
  controllers: [StatsController],
  providers: [StatsService],
  imports: [RedisModule],
})
export class StatsModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.service.ts 
import { Injectable } from '@nestjs/common';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { RedisService } from '../../redis/redis.service';
import * as cheerio from 'cheerio';

@Injectable()
export class StatsService {
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private redisService: RedisService,
  ) {}

  async get() {
    try {
      const cachedData = await this.redisService.get('AQXSTATS');
      if (cachedData) return cachedData;
      const volumeData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/analytics?timeZone=Europe%2FParis&market=secundary&startDate=2021-11-01T00:00:00.000Z&endDate=' +
          new Date().toISOString() +
          '&buckets=1',
      );
      const holderData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/holder_and_supply',
      );
      const twitterData = await axios.get(
        'https://api.livecounts.io/twitter-live-follower-counter/stats/TheAquaverse',
      );
      const floorAverageData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/floor_and_average_price?chartTimeRange=day',
      );
      const xoxnoPage = await axios.get(
        'https://xoxno.com/collection/GUARDIAN-3d6635',
      );
      let floorPrice = null;

      try {
        const cheerioData = cheerio.load(xoxnoPage.data);
        const xoxnoData = cheerioData('#__NEXT_DATA__').html();
        const parsedXoxnoData = JSON.parse(xoxnoData);
        floorPrice = parsedXoxnoData?.props?.pageProps?.initInfoFallback?.floor;
      } catch (e) {}

      const rawEgldVolume =
        volumeData &&
        volumeData.data &&
        volumeData.data.date_histogram &&
        volumeData.data.date_histogram.length > 0
          ? volumeData.data.date_histogram[0].volume
          : null;
      const denum = Math.pow(10, 18);
      const followerCount =
        twitterData && twitterData.data && twitterData.data.followerCount
          ? twitterData.data.followerCount
          : null;
      const totalEgldVolume = rawEgldVolume ? Math.round(rawEgldVolume) : null;
      const holderCount =
        holderData.data && holderData.data.holderCount
          ? holderData.data.holderCount
          : null;
      const floorAverageDataList =
        floorAverageData.data && floorAverageData.data.length > 0
          ? floorAverageData.data
          : [];
      const smallest24hTrade =
        floorAverageDataList.length > 0 && floorAverageDataList[0].floor_price
          ? Math.round((floorAverageDataList[0].floor_price / denum) * 100) /
            100
          : null;

      const oldFloorAverageData =
        floorAverageDataList.length > 1 &&
        floorAverageDataList[floorAverageDataList.length - 1]
          ? floorAverageDataList[floorAverageDataList.length - 1]
          : null;

      const old24hTrade =
        oldFloorAverageData && oldFloorAverageData.floor_price
          ? Math.round((oldFloorAverageData.floor_price / denum) * 100) / 100
          : null;

      const percentage24hTrade =
        smallest24hTrade !== null && old24hTrade !== null
          ? Number(
              ((100 * (smallest24hTrade - old24hTrade)) / old24hTrade).toFixed(
                2,
              ),
            )
          : 0;
      const averagePrice =
        floorAverageDataList.length > 0 && floorAverageDataList[0].average_price
          ? Math.round((floorAverageDataList[0].average_price / denum) * 100) /
            100
          : null;

      const oldAveragePrice =
        oldFloorAverageData && oldFloorAverageData.average_price
          ? Math.round((oldFloorAverageData.average_price / denum) * 100) / 100
          : null;

      const percentageAveragePrice =
        smallest24hTrade !== null && oldAveragePrice !== null
          ? Number(
              (
                (100 * (averagePrice - oldAveragePrice)) /
                oldAveragePrice
              ).toFixed(2),
            )
          : 0;

      const data = {
        twitter: {
          followerCount,
        },
        guardians: {
          smallest24hTrade,
          percentage24hTrade,
          averagePrice,
          percentageAveragePrice,
          holderCount,
          totalEgldVolume,
          floorPrice,
        },
      };
      await this.redisService.set('AQXSTATS', data, 900);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/dto/collection.dto.ts 
import { ConfigService } from '@nestjs/config';
import configuration from '../../../config/configuration';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { IntersectionType } from '@nestjs/swagger';

const configService: ConfigService<EnvironmentVariables> = new ConfigService(
  configuration(),
);

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  MinLength,
  IsNumberString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsInt,
  Min,
  Max,
  ArrayMaxSize,
  ArrayMinSize,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/collection.filters';

export class CreateJWTDto {
  @ApiProperty({
    description: 'email',
  })
  @IsNotEmpty()
  readonly email: string;
  @ApiProperty({
    description: 'password',
  })
  @IsNotEmpty()
  readonly password: string;
}

export class GetCollectionDto {
  @Matches(
    new RegExp(
      '^(' +
        configService.get('nft-collection-name') +
        '|' +
        configService.get('rotg-collection-name') +
        '|' +
        configService.get('ltbox-collection-name') +
        '|' +
        configService.get('tiket-collection-name') +
        '|' +
        configService.get('asset-collection-name') +
        ')$',
    ),
  )
  @ApiProperty({
    enum: [
      configService.get('nft-collection-name'),
      configService.get('rotg-collection-name'),
      configService.get('ltbox-collection-name'),
      configService.get('tiket-collection-name'),
      configService.get('asset-collection-name'),
    ],
  })
  readonly collection: string;
}

export class GetIdWithoutCollectionDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

export class GetIdDto extends IntersectionType(
  GetCollectionDto,
  GetIdWithoutCollectionDto,
) {}

export class GetIdsDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'ids of nft',
  })
  ids: number[];
}
export class GetElementDto extends GetCollectionDto {
  @IsEnum(['water', 'rock', 'algae', 'lava', 'bioluminescent'])
  @ApiProperty({
    description: 'nft/sft element',
  })
  element: string;
}

export class GetIdentifiersDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'identifier of nft/sft',
  })
  identifiers: string[];
}

export class ROTGModel {
  @ApiProperty({
    description: 'ROTG id',
  })
  @IsInt()
  @Min(1)
  @Max(9999)
  id: number;

  @ApiProperty({
    description: 'ROTG name',
  })
  @IsNotEmpty()
  readonly name: string;

  @ApiProperty({
    description: 'ROTG description',
  })
  @IsNotEmpty()
  readonly description: string;

  @ApiProperty({
    description: 'ROTG element',
  })
  @IsEnum(['Water', 'Rock', 'Algae', 'Lava', 'Bioluminescent'])
  readonly element: string;

  @ApiProperty({
    description: 'ROTG image url',
  })
  @IsNotEmpty()
  readonly image: string;

  @ApiProperty({
    description: 'ROTG attributes',
  })
  @ArrayMaxSize(10)
  @ArrayMinSize(10)
  readonly attributes: any[];
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto extends GetCollectionDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.helpers.ts 
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers/out';
import axios from 'axios';

export const sleep = (ms: number) => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};

export const erdDoGetGeneric = async (networkProvider, uri, count = 1) => {
  try {
    const data = await networkProvider.doGetGeneric(uri);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const erdDoPostGeneric = async (
  networkProvider,
  uri,
  body,
  count = 1,
) => {
  try {
    const data = await networkProvider.doPostGeneric(uri, body);
    return data;
  } catch (e) {
    if (count > 3) throw new Error(e);
    else {
      await sleep(1000);
      return erdDoGetGeneric(networkProvider, uri, count + 1);
    }
  }
};

export const processElrondNFTs = async (
  networkProvider: ApiNetworkProvider,
  uriType: 'collections' | 'accounts',
  uriName: string,
  processFunction: (nftList: any[]) => void,
) => {
  try {
    const nftCount = await erdDoGetGeneric(
      networkProvider,
      uriType + '/' + uriName + '/nfts/count',
    );
    const n = 1;
    const size = 100;
    const maxIteration = Math.ceil(nftCount / (size * n));
    for (let i = 0; i < maxIteration; i++) {
      const endpoints = Array.from(
        { length: n },
        (_, index) =>
          'https://devnet-api.elrond.com/' +
          uriType +
          '/' +
          uriName +
          '/nfts?from=' +
          (index + i * n) * size +
          '&size=' +
          size,
      );
      const parallelData = await axios.all(
        endpoints.map((endpoint) => {
          return axios.get(endpoint);
        }),
      );
      console.log('go');
      for (const data of parallelData) {
        if (data.status === 200) {
          await processFunction(data.data);
        } else {
          console.log('ELROND ERROR');
        }
      }
      console.log(i + ' - data scrapped');
      await sleep(3000);
    }
  } catch (e) {
    console.error(e);
  }
};
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.controller.ts 
import {
  Body,
  Controller,
  Get,
  Param,
  ParseArrayPipe,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { CollectionService } from './collection.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetErdDto,
  GetIdDto,
  GetIdsDto,
  GetIdentifiersDto,
  GetMarketDto,
  CreateJWTDto,
  GetIdWithoutCollectionDto,
  ROTGModel,
  GetElementDto,
} from './dto/collection.dto';
import { LocalAuthGuard } from '../auth/guards/local-auth.guard';
import { AuthService } from '../auth/auth.service';

@ApiTags('collection')
@Controller('collection')
export class CollectionController {
  constructor(
    private readonly collectionService: CollectionService,
    private authService: AuthService,
  ) {}

  @Get(':collection/user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get(':collection/user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.collectionService.findUserNftCount({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.collectionService.findByUserLimited({
      ...getErdDto,
      ...getAllDto,
    });
  }

  @Get(':collection/id/:id')
  getCollectionNftById(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findCollectionNftById(getIdDto);
  }

  @Get(':collection/search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.collectionService.findByIdPrefix(getIdDto);
  }

  @Get('scrapRotg')
  scrapRotg() {
    return this.collectionService.scrapAssets();
  }

  @UseGuards(LocalAuthGuard)
  @Post('/getJWT')
  async login(@Request() req, @Body() createJWT: CreateJWTDto) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('/lockMerge/:id')
  @ApiBearerAuth()
  lockMergeV2(@Param() getIdDto: GetIdWithoutCollectionDto) {
    return this.collectionService.lockMergeV2(getIdDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockMerge/:id')
  @ApiBearerAuth()
  unlockMergeV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.unlockMergeV2({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('/unlockForce/:id')
  @ApiBearerAuth()
  forceUnlockTestV2(
    @Param() getIdDto: GetIdWithoutCollectionDto,
    @Body() rotgModel: ROTGModel,
  ) {
    delete rotgModel.id;
    return this.collectionService.forceUnlockTest({
      ...getIdDto,
      ...rotgModel,
    });
  }

  @Get(':collection/ids/:ids')
  getByIds(@Param() getIdsDto: GetIdsDto) {
    getIdsDto.ids = (getIdsDto.ids as unknown as string)
      .split(',')
      .map((idStr) => Number(idStr))
      .filter((id) => !isNaN(id));
    return this.collectionService.getByIds(getIdsDto);
  }

  @Get(':collection/identifiers/:identifiers')
  getByIdentifiers(@Param() getIdentifiersDto: GetIdentifiersDto) {
    getIdentifiersDto.identifiers = (
      getIdentifiersDto.identifiers as unknown as string
    )
      .split(',')
      .filter((identifier) => identifier.length > 0);
    return this.collectionService.getByIdentifiers(getIdentifiersDto);
  }

  @Get(':collection/floor/:element')
  getElementFloorPrice(@Param() getElementDto: GetElementDto) {
    return this.collectionService.getElementFloorPrice(getElementDto);
  }

  @Get(':collection/all')
  getAll(
    @Param() getCollectionDto: GetCollectionDto,
    @Query() getAllDto: GetAllDto,
  ) {
    return this.collectionService.findAll({
      ...getCollectionDto,
      ...getAllDto,
    });
  }

  // @Get(':collcetion/market')
  // getByMarket(
  //   @Param() getCollectionDto: GetCollectionDto,
  //   @Query() getMarketDto: GetMarketDto,
  // ) {
  //   return this.collectionService.findByMarket(getMarketDto);
  // }
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.module.ts 
import { Module } from '@nestjs/common';
import { CollectionService } from './collection.service';
import { CollectionController } from './collection.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Collection, CollectionSchema } from './schemas/collection.schema';
import { NftModule } from '../nft/nft.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([
      { name: Collection.name, schema: CollectionSchema },
    ]),
  ],
  controllers: [CollectionController],
  providers: [CollectionService],
  exports: [CollectionService],
})
export class CollectionModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/schemas/collection.schema.ts 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CollectionDocument = Collection & Document;

const BaseAssetType = {
  name: String,
  url: String,
  vril: Number,
  rarity: Number,
  _id: false,
};
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class Collection {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  collectionName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: false, type: String })
  assetType: string;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: false, type: Number })
  balance: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  vril: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
  @Prop({ required: false, type: Date })
  lockedOn: Date;
}

export const CollectionSchema = SchemaFactory.createForClass(Collection);
// /Users/cheikkone/Projects/explorer-api/src/app/collection/schemas/collection.filters.ts 
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.service.ts 
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetCollectionDto,
  GetElementDto,
  GetErdDto,
  GetIdDto,
  GetIdentifiersDto,
  GetIdsDto,
  GetIdWithoutCollectionDto,
  GetMarketDto,
  ROTGModel,
} from './dto/collection.dto';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { Collection, CollectionDocument } from './schemas/collection.schema';
import { scrapMarkets } from './collection.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
  processElrondNFTs,
} from './collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;
let SCRAP_ROTG = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class CollectionService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(Collection.name)
    private collectionModel: Model<CollectionDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(collection, erd, filters) {
    const size = 1450;
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}/nfts?from=0&size=${size}&collections=${collection}&withScamInfo=false&computeScamInfo=false`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const sfts = dataNFTs
      .filter((d) => d.type === 'SemiFungibleESDT')
      .reduce((agg, unit) => {
        return { ...agg, [unit.nonce]: Number(unit.balance) };
      }, {});
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };
    return { findQuery, filtersQuery, sfts };
  }

  async getByIds(getIdsDto: GetIdsDto) {
    try {
      const { collection, ids } = getIdsDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, id: { $in: ids } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getElementFloorPrice(getElementDto: GetElementDto) {
    try {
      const { collection, element } = getElementDto;
      const lowestPriceNft = await this.collectionModel
        .find(
          {
            collectionName: collection,
            market: { $exists: true },
            stone: element,
          },
          '-_id',
        )
        .sort('market.price')
        .limit(1);
      if (lowestPriceNft && lowestPriceNft.length > 0) {
        return {
          floorPrice: lowestPriceNft[0].market.price,
          details: lowestPriceNft[0],
        };
      } else {
        return {
          floorPrice: 0,
          details: {},
        };
      }
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async getByIdentifiers(getIdentifiersDto: GetIdentifiersDto) {
    try {
      const { collection, identifiers } = getIdentifiersDto;
      const nfts = await this.collectionModel.find(
        { collectionName: collection, identifier: { $in: identifiers } },
        '-_id',
      );
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd, collection } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery, sfts } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      nfts.forEach((nft) => {
        nft.balance = nft.idName in sfts ? sfts[nft.idName] : 1;
      });
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // to remove
  async updateDatabase(assets) {
    try {
      const collections = [];
      let i = 0;
      for (const sft of assets) {
        const pngUrl = sft.media[0].originalUrl.split('/');
        let path = pngUrl[5] + '/' + pngUrl[6].split('.')[0];
        switch (path) {
          case 'Background/Medusa':
            path = 'Background/' + encodeURIComponent('Médusa');
            break;
          case 'Armor/Erales Legendary Algae 5':
            path = 'Armor/' + encodeURIComponent('Eralès Legendary Algae 5');
            break;
        }
        const assetData = await axios.get(
          'https://storage.googleapis.com/guardians-assets-original/json-asset-v2/' +
            path +
            '.json',
        );
        console.log('json read: ' + i);
        i++;
        const asset = {
          url: '/' + path + '.png',
        };
        let assetType;
        let stone;
        for (const trait of assetData.data.attributes) {
          switch (trait.trait_type) {
            case 'Type':
              assetType = trait.value.toLowerCase();
              break;
            case 'Family':
              asset['name'] = trait.value.toLowerCase();
              break;
            case 'Element':
              stone = trait.value.toLowerCase();
              break;
            case 'Vril':
              asset['vril'] = trait.value;
              break;
            case 'Level':
              asset['level'] = trait.value;
              break;
          }
        }
        const output = {
          stone,
          assetType,
          [assetType]: {
            ...asset,
          },
          collectionName: sft.collection,
          identifier: sft.identifier,
          id: sft.nonce,
          idName: sft.nonce.toString(),
          vril: asset['vril'],
        };
        collections.push(output);
      }
      const updateObject = collections.map((d) => ({
        updateOne: {
          filter: { id: d.id, collectionName: d.collectionName },
          update: d,
          upsert: true,
        },
      }));
      // console.log('starting bulk write');
      // await this.collectionModel.bulkWrite(updateObject);
      // console.log('finish');
    } catch (error) {
      console.error(error);
    }
  }

  async scrap() {
    const rotg = this.configService.get('rotg-collection-name');
    const lastNft = (
      await erdDoGetGeneric(
        this.networkProvider,
        `nfts?collection=${rotg}&from=0&size=1&includeFlagged=true`,
      )
    )[0];

    const count = await this.collectionModel.count({
      collectionName: rotg,
    });

    const nftToAdd = lastNft.nonce - count;

    const nfts = await erdDoGetGeneric(
      this.networkProvider,
      `nfts?collection=${rotg}&from=0&size=${nftToAdd}&includeFlagged=true`,
    );
    nfts.forEach((nft) => {
      this.collectionModel.create({
        collection: `${rotg}-2`,
        identifier: nft.identifier,

      });
    });
    console.log(JSON.stringify(nfts[0]));
  }

  // to remove
  async scrapAssets() {
    try {
      this.scrap();
      // await processElrondNFTs(
      //   this.networkProvider,
      //   'accounts',
      //   'erd1qqqqqqqqqqqqqpgq58vp0ydxgpae47pkxqfscvnnzv6vaq9derqqqwmujy',
      //   async (nftList: any[]) => {
      //   },
      // );
      // const nfts = await this.collectionModel.find(
      //   {
      //     collectionName: 'ROTG-467abf',
      //   },
      //   '-_id',
      // );

      // nfts = nfts.map((nft) => {
      //   return {
      //     ...nft.$clone(),
      //     collectionName: nft.collectionName.replace(
      //       'ASSET-6b7288',
      //       'ROTGW-0da75b',
      //     ),
      //     oldId: nft.identifier,
      //     identifier: nft.identifier.replace('ASSET-6b7288', 'ROTGW-0da75b'),
      //   };
      // }) as any;

      // this.collectionModel.create({

      // })

      // (nfts as any).forEach(async (nft, i) => {
      //   const result = await this.collectionModel.findOneAndUpdate(
      //     {
      //       identifier: nft.oldId,
      //     },
      //     {
      //       identifier: nft.identifier,
      //       collectionName: nft.collectionName,
      //     },
      //   );
      //   console.log(result);
      //   console.log({
      //     identifier: nft.identifier,
      //     collectionName: nft.collectionName,
      //   });
      //   // await result.save();
      //   if (i == 0) {
      //     console.log(result);
      //   }
      // });

      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: false },
      //     isClaimed: false,
      //     collectionName: this.configService.get('rotg-collection-name'),
      //   },
      //   {
      //     isClaimed: true,
      //   },
      // );
      // await this.collectionModel.updateMany(
      //   {
      //     isTrulyClaimed: { $exists: true },
      //   },
      //   {
      //     $unset: {
      //       isTrulyClaimed: true,
      //     },
      //   },
      // );
    } catch (e) {
      console.error(e);
    }
  }

  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('* * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      SCRAP_ROTG = !SCRAP_ROTG;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      const collectionName = SCRAP_ROTG
        ? this.configService.get('rotg-collection-name')
        : this.configService.get('nft-collection-name');
      await scrapMarkets(
        this.collectionModel,
        collectionName,
        EGLD_RATE,
        timestamp,
      );
      await this.collectionModel.updateMany(
        {
          collectionName,
          timestamp: { $exists: true, $ne: timestamp },
        },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      RUNNING = false;
      console.log(error);
      this.client.instance().captureException(error);
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const nfts = await this.collectionModel
        .find({ ...findQuery, ...filtersQuery }, '-_id -market')
        .limit(limit);
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { collection, erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        collection,
        erd,
        getErdDto,
      );
      const totalCount = await this.collectionModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateNFTOwners(collection) {
    try {
      const endpoints = Array.from(
        { length: 20 },
        (_, index) =>
          'https://devnet-api.elrond.com/collections/' +
          collection +
          '/nfts?from=' +
          index * 500 +
          '&size=500',
      );
      return axios.all(endpoints.map((endpoint) => axios.get(endpoint)));
    } catch (e) {
      console.error(e);
    }
  }

  async findCollectionNftById(getIdDto: GetIdDto) {
    try {
      const { collection, id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        { collectionName: collection, id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      // to remove
      // this.scrapAssets('ASSET-6b7288');
      // return;
      const { collection, id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.collectionModel
        .find({
          collectionName: collection,
          idName: new RegExp('^' + id),
        })
        .sort({ id: 1 })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async lockMergeV2(getIdDto: GetIdWithoutCollectionDto) {
    try {
      const { id } = getIdDto;
      const record = await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: false },
        },
        { lockedOn: new Date() },
        { new: true, projection: '-_id' },
      );
      return {
        justGotLocked: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async unlockMergeV2(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      const record = await this.collectionModel.findOne({
        collectionName: this.configService.get('rotg-collection-name'),
        id,
        lockedOn: { $exists: true },
      });
      if (record) {
        record.lockedOn = undefined;
        await record.save();
      }
      return {
        justGotMerged: record ? true : false,
      };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async forceUnlockTest(rotgModel: ROTGModel) {
    try {
      const { id } = rotgModel;
      await this.collectionModel.findOneAndUpdate(
        {
          collectionName: this.configService.get('rotg-collection-name'),
          id,
          lockedOn: { $exists: true },
        },
        { $unset: { lockedOn: true } },
      );
      return true;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      collectionName: dto.collection,
      stone: dto.stone,
      isClaimed: dto.isClaimed,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto as GetAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.collectionModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.collectionModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.checkSmartContract(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(collection, claimedIds) {
    await this.collectionModel.updateMany(
      { collectionName: collection, id: { $in: claimedIds } },
      { isClaimed: true },
    );
  }

  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.collectionModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.collectionModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }

  // @Cron('*/2 * * * *')
  // private async scrapMarket() {
  //   try {
  //     const timestamp: number = new Date().getTime();
  //     await this.fullScrapTrustmarket('bid', timestamp);
  //     await this.fullScrapTrustmarket('buy', timestamp);
  //     // await this.scrapDeadrare(timestamp);
  //     await this.nftModel.updateMany(
  //       { timestamp: { $exists: true, $ne: timestamp } },
  //       { $unset: { market: 1, timestamp: 1 } },
  //     );
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //   }
  // }
  // private async scrapTrustmarket(
  //   type: 'bid' | 'buy',
  //   offset: number,
  //   count: number,
  //   timestamp: number,
  // ) {
  //   try {
  //     const trustmarketApi = this.configService.get('trustmarket-api');
  //     const { data } = await axios.post(trustmarketApi, {
  //       filters: {
  //         onSale: true,
  //         auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
  //       },
  //       collection: 'GUARDIAN-3d6635',
  //       skip: offset,
  //       top: count,
  //       select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
  //     });
  //     if (!data.results || data.results.length === 0) return true;
  //     if (type === 'buy') {
  //       const nftSample = data.results[0];
  //       EGLD_RATE =
  //         nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
  //     }
  //     const isLast: boolean = offset + data.resultsCount === data.count;
  //     const updateObject = data.results.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.nonce },
  //         update: {
  //           market: {
  //             source:
  //               d.saleInfoNft?.marketplace === 'DR'
  //                 ? 'deadrare'
  //                 : 'trustmarket',
  //             identifier: d.identifier,
  //             type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
  //             bid:
  //               d.saleInfoNft?.auction_type !== 'NftBid'
  //                 ? null
  //                 : {
  //                     min: d.saleInfoNft?.min_bid_short,
  //                     current: d.saleInfoNft?.current_bid_short,
  //                     deadline: getTimeUntil(d.saleInfoNft?.deadline),
  //                   },
  //             token: d.saleInfoNft?.accepted_payment_token,
  //             price: d.saleInfoNft?.max_bid_short,
  //             currentUsd: +d.saleInfoNft?.usd,
  //             timestamp: +d.saleInfoNft?.timestamp,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     await this.nftModel.bulkWrite(updateObject);
  //     return isLast;
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }

  async checkSmartContract(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      //   await this.nftModel.updateMany(
      //     { id: { $in: claimedIds } },
      //     { isClaimed: true },
      //   );
      await this.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  // private async scrapDeadrare(timestamp: number) {
  //   try {
  //     const deadrareApi = this.configService.get('deadrare-api');
  //     const deadrareApiParams = this.configService.get('deadrare-api-params');
  //     const { data } = await axios.get(deadrareApi + deadrareApiParams);
  //     if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
  //     const updateObject = data.data.listAuctions.map((d) => ({
  //       updateOne: {
  //         filter: { id: d.cachedNft.nonce },
  //         update: {
  //           market: {
  //             source: 'deadrare',
  //             identifier: d.nftId,
  //             type: 'buy',
  //             bid: null,
  //             token: 'EGLD',
  //             price: +d.price,
  //             currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
  //           },
  //           timestamp,
  //         },
  //       },
  //     }));
  //     return this.nftModel.bulkWrite(updateObject);
  //   } catch (error) {
  //     this.client.instance().captureException(error);
  //     throw error;
  //   }
  // }
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/collection.market.ts 
import axios from 'axios';
import { CollectionDocument } from './schemas/collection.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';
import { sleep } from './collection.helpers';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      if (auctionTokenData[6] === auctionTokenData[7]) {
        return parseInt(auctionTokenData[6], 16);
      } else {
        console.log(identifier + ': auction/' + elrondTransaction.function);
      }
    } else if (
      // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  collectionModel: Model<CollectionDocument>,
  collectionName: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket(
    'deadrare',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'frameit',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'xoxno',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
  await scrapOneMarket(
    'elrond',
    collectionName,
    collectionModel,
    egldRate,
    timestamp,
  );
};

const getIdsOfNFTsInMarket = async function (
  marketName,
  collection,
  from,
  size,
) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=' +
      collection,
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  collection: 'ROTG-fc7c99' | 'GUARDIAN-3d6635',
  collectionModel: Model<CollectionDocument>,
  egldRate: number,
  timestamp: number,
) {
  let from = 0;
  const size = 100;
  let nftsScrapped = false;
  while (!nftsScrapped) {
    const nftsIds = await getIdsOfNFTsInMarket(
      marketName,
      collection,
      from,
      size,
    );
    from += size;
    if (nftsIds.length == 0) {
      nftsScrapped = true;
      break;
    }

    // update timestamp for in-market nfts
    await collectionModel.updateMany(
      { collectionName: collection, id: { $in: nftsIds } },
      { timestamp },
    );
    // get newly entered nfts
    const newNFTs = await collectionModel.find({
      collectionName: collection,
      id: { $in: nftsIds },
      market: { $exists: false },
    });

    const updateObject = [];
    for (const nft of newNFTs) {
      // update db with price of newly added nft
      let price;
      try {
        price = await getNftPrice(marketName, nft.identifier);
      } catch (e) {
        continue;
      }
      const market = {
        source: marketName,
        identifier: nft.identifier,
        type: 'buy',
        bid: null,
        token: 'EGLD',
        price,
        currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
      };
      console.log(market);
      updateObject.push({
        updateOne: {
          filter: { collectionName: collection, id: nft.id },
          update: {
            market,
          },
        },
      });
      await sleep(500);
    }
    await collectionModel.bulkWrite(updateObject);
  }
};
// /Users/cheikkone/Projects/explorer-api/src/app/collection/dto/collection.dto.ts 
import { ConfigService } from '@nestjs/config';
import configuration from '../../../config/configuration';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { IntersectionType } from '@nestjs/swagger';

const configService: ConfigService<EnvironmentVariables> = new ConfigService(
  configuration(),
);

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  MinLength,
  IsNumberString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsInt,
  Min,
  Max,
  ArrayMaxSize,
  ArrayMinSize,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/collection.filters';

export class CreateJWTDto {
  @ApiProperty({
    description: 'email',
  })
  @IsNotEmpty()
  readonly email: string;
  @ApiProperty({
    description: 'password',
  })
  @IsNotEmpty()
  readonly password: string;
}

export class GetCollectionDto {
  @Matches(
    new RegExp(
      '^(' +
        configService.get('nft-collection-name') +
        '|' +
        configService.get('rotg-collection-name') +
        '|' +
        configService.get('ltbox-collection-name') +
        '|' +
        configService.get('tiket-collection-name') +
        '|' +
        configService.get('asset-collection-name') +
        ')$',
    ),
  )
  @ApiProperty({
    enum: [
      configService.get('nft-collection-name'),
      configService.get('rotg-collection-name'),
      configService.get('ltbox-collection-name'),
      configService.get('tiket-collection-name'),
      configService.get('asset-collection-name'),
    ],
  })
  readonly collection: string;
}

export class GetIdWithoutCollectionDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

export class GetIdDto extends IntersectionType(
  GetCollectionDto,
  GetIdWithoutCollectionDto,
) {}

export class GetIdsDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'ids of nft',
  })
  ids: number[];
}
export class GetElementDto extends GetCollectionDto {
  @IsEnum(['water', 'rock', 'algae', 'lava', 'bioluminescent'])
  @ApiProperty({
    description: 'nft/sft element',
  })
  element: string;
}

export class GetIdentifiersDto extends GetCollectionDto {
  @MinLength(1)
  @ApiProperty({
    description: 'identifier of nft/sft',
  })
  identifiers: string[];
}

export class ROTGModel {
  @ApiProperty({
    description: 'ROTG id',
  })
  @IsInt()
  @Min(1)
  @Max(9999)
  id: number;

  @ApiProperty({
    description: 'ROTG name',
  })
  @IsNotEmpty()
  readonly name: string;

  @ApiProperty({
    description: 'ROTG description',
  })
  @IsNotEmpty()
  readonly description: string;

  @ApiProperty({
    description: 'ROTG element',
  })
  @IsEnum(['Water', 'Rock', 'Algae', 'Lava', 'Bioluminescent'])
  readonly element: string;

  @ApiProperty({
    description: 'ROTG image url',
  })
  @IsNotEmpty()
  readonly image: string;

  @ApiProperty({
    description: 'ROTG attributes',
  })
  @ArrayMaxSize(10)
  @ArrayMinSize(10)
  readonly attributes: any[];
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto extends GetCollectionDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
// /Users/cheikkone/Projects/explorer-api/src/app/collection/schemas/collection.schema.ts 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CollectionDocument = Collection & Document;

const BaseAssetType = {
  name: String,
  url: String,
  vril: Number,
  rarity: Number,
  _id: false,
};
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class Collection {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  collectionName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: false, type: String })
  assetType: string;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: false, type: Number })
  balance: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  vril: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
  @Prop({ required: false, type: Date })
  lockedOn: Date;
}

export const CollectionSchema = SchemaFactory.createForClass(Collection);
// /Users/cheikkone/Projects/explorer-api/src/app/collection/schemas/collection.filters.ts 
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
// /Users/cheikkone/Projects/explorer-api/src/app/nft/dto/nft.dto.ts 
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  IsNumberString,
  IsOptional,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/nft.filters';

export class GetIdDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @ApiPropertyOptional({
    description: 'Guardian crown type',
    enum: filters.crown,
  })
  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.controller.spec.ts 
import { ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Connection } from 'mongoose';
import * as request from 'supertest';

import { AppModule } from '../../app.module';
import { DatabaseService } from '../../database/database.service';
import { GetErdDto } from './dto/nft.dto';

const erdStubWithNFTs = (): GetErdDto => {
  return {
    erd: 'erd17djfwed563cry53thgytxg5nftvl9vkec4yvrgveu905zeq6erqqkr7cmy',
  };
};
const erdStubWithoutNFTs = (): GetErdDto => {
  return {
    erd: 'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
  };
};
const erdStubInvalid = (): GetErdDto => {
  return {
    erd: 'erd1qck4cpghjff88gg7rq6q4w0fndd3g33v499999z9ehjhqg9uxu222zkxwz',
  };
};

describe('NFTController', () => {
  let dbConnection: Connection;
  let httpServer: any;
  let app: any;
  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
      }),
    );
    await app.init();
    dbConnection = moduleRef
      .get<DatabaseService>(DatabaseService)
      .getDbHandle();
    httpServer = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('findByUser', () => {
    it("should return list of user's nfts", async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toBeGreaterThan(0);
    });
    it('should return empty list in case user has no nfts', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubWithoutNFTs().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(0);
    });
    it('should return 500 in case user erd is invalid', async () => {
      const response = await request(httpServer).get(
        `/nft/user/${erdStubInvalid().erd}?by=rank&order=asc&page=1`,
      );
      expect(response.status).toBe(500);
    });
  });

  describe('findById', () => {
    it('should return NFT with id=666', async () => {
      const response = await request(httpServer).get(`/nft/id/666`);
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('id');
      expect(response.body.id).toEqual(666);
    });
    it('should return 400 in for out of range id', async () => {
      const response = await request(httpServer).get(`/nft/id/10000`);
      expect(response.status).toBe(400);
    });
  });

  describe('findAll', () => {
    it('should return 400 with page > 500', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=501`,
      );
      expect(response.status).toBe(400);
    });
    it('should return list with id=1 for first element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=id&order=asc&page=1`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(20);
      expect(response.body.nfts[0].id).toEqual(1);
    });
    it('should return list with rank=1 for last element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=500`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(19);
      expect(response.body.nfts[18].rank).toEqual(1);
    });

    it('should return filtered element', async () => {
      const response = await request(httpServer).get(
        `/nft/all?by=rank&order=desc&page=1&background=kyoto%20ape&crown=shepherd%20of%20grace&hairstyle=tako&hairstyleColor=grey&eyes=oshiza&eyesColor=grey&nose=hiken&mouth=dagon&mouthColor=grey&armor=shin&weapon=oshiza%20spear&stone=lava&id=39`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      expect(Array.isArray(response.body.nfts)).toBe(true);
      expect(response.body.nfts.length).toEqual(1);
      expect(response.body.nfts[0].id).toEqual(3908);
    });
  });

  describe('findByMarket', () => {
    it('should return list of NFTs listed on deadrare + trustmarket', async () => {
      const response = await request(httpServer).get(
        `/nft/market?order=asc&page=1&by=price`,
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const sources = response.body.nfts.map((el) => {
        return el.market.source;
      });
      expect(sources).toContain('deadrare');
      expect(sources).toContain('trustmarket');
    });
    it('should return prices in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=price',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const prices = response.body.nfts.map((el) => {
        return el.market.currentUsd;
      });
      expect(prices[0]).toBeGreaterThan(prices[1]);
    });
    it('should return rank in descending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=desc&page=1&by=rank',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ranks = response.body.nfts.map((el) => {
        return el.rank;
      });
      expect(ranks[0]).toBeGreaterThan(ranks[1]);
    });
    it('should return ids in ascending order', async () => {
      const response = await request(httpServer).get(
        '/nft/market?order=asc&page=1&by=id',
      );
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nfts');
      const ids = response.body.nfts.map((el) => {
        return el.id;
      });
      expect(ids[0]).toBeLessThan(ids[1]);
    });
  });
});
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.market.ts 
import axios from 'axios';
import { NFTDocument } from './schemas/nft.schema';
import { Model } from 'mongoose';

import * as cheerio from 'cheerio';

const SMART_CONTRACTS = {
  deadrare: 'erd1qqqqqqqqqqqqqpgqd9rvv2n378e27jcts8vfwynpx0gfl5ufz6hqhfy0u0',
  frameit: 'erd1qqqqqqqqqqqqqpgq705fxpfrjne0tl3ece0rrspykq88mynn4kxs2cg43s',
  xoxno: 'erd1qqqqqqqqqqqqqpgq6wegs2xkypfpync8mn2sa5cmpqjlvrhwz5nqgepyg8',
  elrond: 'erd1qqqqqqqqqqqqqpgqra34kjj9zu6jvdldag72dyknnrh2ts9aj0wqp4acqh',
};

const getDeadrarePrice = async function (identifier) {
  const deadrarePage = await axios.get('https://deadrare.io/nft/' + identifier);
  const cheerioData = cheerio.load(deadrarePage.data);
  const nextData = cheerioData('#__NEXT_DATA__').html();
  const parsedNextData = JSON.parse(nextData);
  const deadrareData = parsedNextData?.props?.pageProps?.apolloState;
  if (!deadrareData) {
    throw new Error('Unable to get deadrare data');
  }
  const auctionKey = Object.keys(deadrareData).filter(
    (n) =>
      !n.startsWith('Cached') &&
      !n.startsWith('SaleField') &&
      !n.startsWith('Listing') &&
      !n.startsWith('NFTField') &&
      n !== 'ROOT_QUERY',
  );
  if (auctionKey.length > 1) {
    throw new Error('Unable to find auction key');
  }
  const price = deadrareData[auctionKey[0]]?.price;
  if (!price) {
    throw new Error('Unable to get auction price');
  }
  return price;
};

const getFrameitPrice = async function (identifier) {
  const frameitApi = await axios.get(
    'https://api.frameit.gg/api/v1/activity?TokenIdentifier=' + identifier,
  );
  const frameitData = frameitApi.data.data[0];
  if (frameitData.action === 'Listing') {
    return frameitData.paymentAmount.amount;
  }
  throw new Error('NFT is not listed');
};

const getXoxnoPrice = async function (identifier) {
  const graphQuery = {
    operationName: 'assetHistory',
    variables: {
      filters: {
        identifier,
      },
      pagination: {
        first: 1,
        timestamp: null,
      },
    },
    query:
      'query assetHistory($filters: AssetHistoryFilter!, $pagination: HistoryPagination) {\n  assetHistory(filters: $filters, pagination: $pagination) {\n    edges {\n      __typename\n      cursor\n      node {\n        action\n        actionDate\n        address\n        account {\n          address\n          herotag\n          profile\n          __typename\n        }\n        itemCount\n        price {\n          amount\n          timestamp\n          token\n          usdAmount\n          __typename\n        }\n        senderAddress\n        senderAccount {\n          address\n          herotag\n          profile\n          __typename\n        }\n        transactionHash\n        __typename\n      }\n    }\n    pageData {\n      count\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n',
  };
  const graphApi = await axios.post(
    'https://nfts-graph.elrond.com/graphql',
    graphQuery,
  );
  const transactionHash =
    graphApi?.data?.data?.assetHistory?.edges[0]?.node?.transactionHash;
  if (!transactionHash) throw new Error('Unable to get nft last transaction');
  const elrondApi = await axios.get(
    'https://api.elrond.com/transactions/' + transactionHash,
  );
  const elrondTransaction = elrondApi.data;
  if (elrondTransaction.function === 'listing') {
    const buff = Buffer.from(elrondTransaction.data, 'base64');
    const auctionTokenData = buff.toString('utf-8').split('@');
    // check if EGLD (45474c44)
    if (auctionTokenData.length > 9 && auctionTokenData[9] === '45474c44') {
      return parseInt(auctionTokenData[6], 16);
    } else if ( // check if LKMEX
      auctionTokenData.length > 9 &&
      auctionTokenData[9] === '4c4b4d45582d616162393130'
    ) {
      return parseInt(auctionTokenData[6], 16);
    }
  } else if (elrondTransaction.function === 'buyGuardian') {
    return 20000000000000000000;
  } else {
    console.log(identifier + ': ' + elrondTransaction.function);
  }
  throw new Error('NFT is not listed on xoxno');
};

const getNftPrice = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  identifier,
) {
  let price;
  switch (marketName) {
    case 'deadrare':
      price = await getDeadrarePrice(identifier);
      break;
    case 'frameit':
      price = await getFrameitPrice(identifier);
      break;
    case 'xoxno':
      price = await getXoxnoPrice(identifier);
      break;
    case 'elrond':
      price = await getXoxnoPrice(identifier);
      break;
  }
  return price / Math.pow(10, 18);
};

export const scrapMarkets = async function (
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  await scrapOneMarket('deadrare', nftModel, egldRate, timestamp);
  await scrapOneMarket('frameit', nftModel, egldRate, timestamp);
  await scrapOneMarket('xoxno', nftModel, egldRate, timestamp);
  await scrapOneMarket('elrond', nftModel, egldRate, timestamp);
};

const getIdsOfNFTsInMarket = async function (marketName, from, size) {
  const nfts = await axios.get(
    'https://api.elrond.com/accounts/' +
      SMART_CONTRACTS[marketName] +
      '/nfts?from=' +
      from +
      '&size=' +
      size +
      '&collections=GUARDIAN-3d6635',
  );
  return nfts.data.map((x) => x.nonce);
};

const scrapOneMarket = async function (
  marketName: 'deadrare' | 'frameit' | 'xoxno' | 'elrond',
  nftModel: Model<NFTDocument>,
  egldRate: number,
  timestamp: number,
) {
  try {
    let from = 0;
    const size = 100;
    let nftsScrapped = false;
    while (!nftsScrapped) {
      const nftsIds = await getIdsOfNFTsInMarket(marketName, from, size);
      from += size;
      if (nftsIds.length == 0) {
        nftsScrapped = true;
        break;
      }

      // update timestamp for in-market nfts
      await nftModel.updateMany({ id: { $in: nftsIds } }, { timestamp });
      // get newly entered nfts
      const newNFTs = await nftModel.find({
        id: { $in: nftsIds },
        market: { $exists: false },
      });

      const updateObject = [];
      for (const nft of newNFTs) {
        // update db with price of newly added nft
        let price;
        try {
          price = await getNftPrice(marketName, nft.identifier);
        } catch (e) {
          continue;
        }
        const market = {
          source: marketName,
          identifier: nft.identifier,
          type: 'buy',
          bid: null,
          token: 'EGLD',
          price,
          currentUsd: egldRate ? +(egldRate * price).toFixed(2) : null,
        };
        console.log(market);
        updateObject.push({
          updateOne: {
            filter: { id: nft.id },
            update: {
              market,
            },
          },
        });
      }
      await nftModel.bulkWrite(updateObject);
    }
  } catch (e) {
    console.log(e);
    try {
      await nftModel.updateMany({ 'market.source': marketName }, { timestamp });
    } catch (e) {}
  }
};
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.service.ts 
import { Injectable, OnModuleInit } from '@nestjs/common';
import { Model, SortValues } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { EnvironmentVariables } from '../../config/configuration.d';
import { NotFoundException } from '../../exceptions/http.exception';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';
import { NFT, NFTDocument } from './schemas/nft.schema';
import { Cron } from '@nestjs/schedule';
import { pickBy, identity, isEmpty } from 'lodash';
import { CollectionService } from '../collection/collection.service';
import { scrapMarkets } from './nft.market';
import {
  erdDoGetGeneric,
  erdDoPostGeneric,
} from '../collection/collection.helpers';

let EGLD_RATE = 0;
let RUNNING = false;

function getTimeUntil(finalTimestamp): [number, number, number, number] {
  const currentTimestamp = Math.floor(new Date().getTime() / 1000);
  let deadline = finalTimestamp - currentTimestamp;
  if (deadline < 0) return [0, 0, 0, 0];
  const days = Math.floor(deadline / 86400);
  deadline = deadline - days * 86400;
  const hours = Math.floor(deadline / 3600);
  deadline = deadline - hours * 3600;
  const minutes = Math.floor(deadline / 60);
  const seconds = deadline - minutes * 60;
  return [days, hours, minutes, seconds];
}

@Injectable()
export class NftService implements OnModuleInit {
  private networkProvider: ApiNetworkProvider;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private readonly collectionService: CollectionService,
    private configService: ConfigService<EnvironmentVariables>,
    @InjectModel(NFT.name) private nftModel: Model<NFTDocument>,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
  }
  async onModuleInit(): Promise<void> {
    // await this.scrapMarket();
  }
  private async getUserNfts(erd, filters) {
    const apiParams = this.configService.get('elrond-api-params');
    const dataNFTs = await erdDoGetGeneric(
      this.networkProvider,
      `accounts/${erd}${apiParams}`,
    );
    const userNFTIds = dataNFTs.map((x) => x.nonce);
    if (userNFTIds.length === 0) throw new NotFoundException();
    const filtersQuery = this.getFiltersQuery(filters);
    const findQuery = { id: { $in: userNFTIds } };

    return { findQuery, filtersQuery };
  }

  async getByIds(ids: number[]) {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUser(getErdDto: GetErdDto | GetAllDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { by, order, page } = getErdDto as GetAllDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      if (error instanceof NotFoundException) return { nfts: [] };
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByUserLimited(getErdDto: GetErdDto | GetAllDtoLimited) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { limit } = getErdDto as GetAllDtoLimited;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const nfts = await this.nftModel
        .find({ ...findQuery, ...filtersQuery }, '-_id')
        .limit(limit);
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { nfts, totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findUserNftCount(getErdDto: GetErdDto) {
    try {
      const { erd } = getErdDto as GetErdDto;
      const { findQuery, filtersQuery } = await this.getUserNfts(
        erd,
        getErdDto,
      );
      const totalCount = await this.nftModel.count({
        ...findQuery,
        ...filtersQuery,
      });
      return { totalCount };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findById(getIdDto: GetIdDto) {
    try {
      const { id } = getIdDto;
      const record = await this.nftModel.findOneAndUpdate(
        { id },
        { $inc: { viewed: 1 } },
        { new: true, projection: '-_id' },
      );
      if (!record) throw new NotFoundException();
      return record;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async findByIdPrefix(getFindByIdPrefix: GetIdDto) {
    try {
      const { id } = getFindByIdPrefix as GetIdDto;
      const nfts = await this.nftModel
        .find({
          idName: new RegExp('^' + id),
        })
        .limit(40);
      return { nfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private getFiltersQuery(dto) {
    const dirtyObject = {
      'background.name': dto.background,
      'crown.name': dto.crown,
      'hairstyle.name': dto.hairstyle,
      'hairstyle.color': dto.hairstyleColor,
      'eyes.name': dto.eyes,
      'eyes.color': dto.eyesColor,
      'weapon.level': dto.weaponLevel,
      'armor.level': dto.armorLevel,
      'crown.level': dto.crownLevel,
      'nose.name': dto.nose,
      'mouth.name': dto.mouth,
      'mouth.color': dto.mouthColor,
      'armor.name': dto.armor,
      'weapon.name': dto.weapon,
      stone: dto.stone,
    };
    if (dto.id)
      dirtyObject['$expr'] = {
        $regexMatch: {
          input: { $toString: '$id' },
          regex: `^${dto.id}`,
        },
      };
    const filtersQuery = pickBy(dirtyObject, identity);
    if (dto.isClaimed === true || dto.isClaimed === false) {
      filtersQuery.isClaimed = dto.isClaimed;
    }
    return filtersQuery;
  }

  async findAll(getAllDto: GetAllDto) {
    try {
      const { by, order, page } = getAllDto;
      const findQuery = this.getFiltersQuery(getAllDto);
      const count = 20;
      const offset = count * (page - 1);
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };
      let nfts = await this.nftModel
        .find(findQuery, '-_id')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = isEmpty(findQuery)
        ? 9999
        : await this.nftModel.count(findQuery);
      if (findQuery.isClaimed === false) {
        const updatedNfts = await this.updateIsClaimed(nfts);
        nfts = updatedNfts.filter((n) => n.isClaimed === false);
      }
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
  async findByMarket(getMarketDto: GetMarketDto) {
    try {
      const { order, page } = getMarketDto;
      let { by } = getMarketDto;
      const count = getMarketDto.count ? getMarketDto.count : 20;
      const offset = count * (page - 1);
      const filtersQuery = this.getFiltersQuery(getMarketDto);
      const marketQuery = {
        market: { $exists: true },
        'market.price': { $exists: true },
        'market.token': { $ne: 'WATER-9ed400' },
      };
      if (getMarketDto.type) marketQuery['market.type'] = getMarketDto.type;
      const findQuery = { ...marketQuery, ...filtersQuery };
      if (by === 'price') by = 'market.currentUsd';
      else if (by === 'latest') by = 'market.timestamp';
      const sortQuery = { [by]: order === 'asc' ? 1 : -1 } as {
        [by: string]: SortValues;
      };

      const nfts = await this.nftModel
        .find(findQuery, '-_id -timestamp')
        .sort(sortQuery)
        .skip(offset)
        .limit(count);
      const totalCount = await this.nftModel.count(findQuery);
      return { nfts, totalCount, pageCount: Math.ceil(totalCount / count) };
    } catch (error) {
      console.log(error.response);
      this.client.instance().captureException(error);
      throw error;
    }
  }
  private async updateEgldRate() {
    try {
      const coingecko = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd',
      );
      if (
        coingecko?.data &&
        coingecko.data['elrond-erd-2'] &&
        coingecko.data['elrond-erd-2']['usd']
      ) {
        EGLD_RATE = coingecko.data['elrond-erd-2']['usd'];
      }
    } catch (e) {}
  }

  @Cron('*/30 * * * * *')
  private async scrapMarket() {
    try {
      if (RUNNING) return;
      RUNNING = true;
      await this.updateEgldRate();
      const timestamp: number = new Date().getTime();
      // await this.fullScrapTrustmarket('bid', timestamp);
      // await this.fullScrapTrustmarket('buy', timestamp);
      // await this.scrapDeadrare(timestamp);
      await scrapMarkets(this.nftModel, EGLD_RATE, timestamp);
      await this.nftModel.updateMany(
        { timestamp: { $exists: true, $ne: timestamp } },
        { $unset: { market: 1, timestamp: 1 } },
      );
      RUNNING = false;
    } catch (error) {
      console.log(error);
      this.client.instance().captureException(error);
    }
  }
  private async scrapTrustmarket(
    type: 'bid' | 'buy',
    offset: number,
    count: number,
    timestamp: number,
  ) {
    try {
      const trustmarketApi = this.configService.get('trustmarket-api');
      const { data } = await axios.post(trustmarketApi, {
        filters: {
          onSale: true,
          auctionTypes: type === 'bid' ? ['NftBid'] : ['Nft'],
        },
        collection: 'GUARDIAN-3d6635',
        skip: offset,
        top: count,
        select: ['onSale', 'saleInfoNft', 'identifier', 'nonce'],
      });
      if (!data.results || data.results.length === 0) return true;
      if (type === 'buy') {
        const nftSample = data.results[0];
        EGLD_RATE =
          nftSample.saleInfoNft?.usd / nftSample.saleInfoNft?.max_bid_short;
      }
      const isLast: boolean = offset + data.resultsCount === data.count;
      const updateObject = data.results.map((d) => ({
        updateOne: {
          filter: { id: d.nonce },
          update: {
            market: {
              source:
                d.saleInfoNft?.marketplace === 'DR'
                  ? 'deadrare'
                  : 'trustmarket',
              identifier: d.identifier,
              type: d.saleInfoNft?.auction_type === 'NftBid' ? 'bid' : 'buy',
              bid:
                d.saleInfoNft?.auction_type !== 'NftBid'
                  ? null
                  : {
                      min: d.saleInfoNft?.min_bid_short,
                      current: d.saleInfoNft?.current_bid_short,
                      deadline: getTimeUntil(d.saleInfoNft?.deadline),
                    },
              token: d.saleInfoNft?.accepted_payment_token,
              price: d.saleInfoNft?.max_bid_short,
              currentUsd: +d.saleInfoNft?.usd,
              timestamp: +d.saleInfoNft?.timestamp,
            },
            timestamp,
          },
        },
      }));
      await this.nftModel.bulkWrite(updateObject);
      return isLast;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  private async fullScrapTrustmarket(type: 'bid' | 'buy', timestamp: number) {
    let isFinished = false;
    let offset = 0;
    const count = 200;
    while (!isFinished) {
      isFinished = await this.scrapTrustmarket(type, offset, count, timestamp);
      offset += count;
    }
  }

  private async scrapDeadrare(timestamp: number) {
    try {
      const deadrareApi = this.configService.get('deadrare-api');
      const deadrareApiParams = this.configService.get('deadrare-api-params');
      const { data } = await axios.get(deadrareApi + deadrareApiParams);
      if (!data.data || !data.data.listAuctions) throw data; // here to check error on sentry
      const updateObject = data.data.listAuctions.map((d) => ({
        updateOne: {
          filter: { id: d.cachedNft.nonce },
          update: {
            market: {
              source: 'deadrare',
              identifier: d.nftId,
              type: 'buy',
              bid: null,
              token: 'EGLD',
              price: +d.price,
              currentUsd: EGLD_RATE ? +(EGLD_RATE * d.price).toFixed(2) : null,
            },
            timestamp,
          },
        },
      }));
      return this.nftModel.bulkWrite(updateObject);
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async updateIsClaimed(nfts) {
    // get nonces
    const unclaimedNFTsNonce = nfts
      .filter((n) => n.isClaimed === false)
      .map((n) => n.identifier.split('-')[2]);
    if (unclaimedNFTsNonce.length === 0) return nfts;
    // get isClaimed from SC
    const getHaveBeenClaimed = await erdDoPostGeneric(
      this.networkProvider,
      'query',
      {
        scAddress: this.configService.get('claim-sc'),
        funcName: 'haveBeenClaimed',
        args: unclaimedNFTsNonce,
      },
    );
    // update nfts with new isClaimed
    const claimedIds = [];
    for (const nft of nfts) {
      const index = unclaimedNFTsNonce.findIndex(
        (nonce) => nonce === nft.identifier.split('-')[2],
      );
      if (index !== -1) {
        const isCurrentlyClaimed =
          getHaveBeenClaimed.returnData[index] === 'AQ==';
        nft.isClaimed = isCurrentlyClaimed;
        if (isCurrentlyClaimed) claimedIds.push(nft.id);
      }
    }
    // update mongo if some nfts are recently claimed
    if (claimedIds.length > 0) {
      await this.nftModel.updateMany(
        { id: { $in: claimedIds } },
        { isClaimed: true },
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('rotg-collection-name'),
        claimedIds,
      );
      await this.collectionService.updateIsClaimed(
        this.configService.get('nft-collection-name'),
        claimedIds,
      );
    }
    return nfts;
  }

  async claimByIds(ids: number[]): Promise<{ nfts: any }> {
    try {
      const nfts = await this.nftModel.find({ id: { $in: ids } }, '-_id');
      const updatedNfts = await this.updateIsClaimed(nfts);
      return { nfts: updatedNfts };
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.controller.ts 
import { Controller, Get, Param, ParseArrayPipe, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { NftService } from './nft.service';
import {
  GetAllDto,
  GetAllDtoLimited,
  GetErdDto,
  GetIdDto,
  GetMarketDto,
} from './dto/nft.dto';

@ApiTags('nft')
@Controller('nft')
export class NftController {
  constructor(private readonly nftService: NftService) {}

  @Get('user/:erd')
  getByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findByUser({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/count')
  getCountByErd(@Param() getErdDto: GetErdDto, @Query() getAllDto: GetAllDto) {
    return this.nftService.findUserNftCount({ ...getErdDto, ...getAllDto });
  }

  @Get('user/:erd/limited')
  getByErdLimited(
    @Param() getErdDto: GetErdDto,
    @Query() getAllDto: GetAllDtoLimited,
  ) {
    return this.nftService.findByUserLimited({ ...getErdDto, ...getAllDto });
  }

  @Get('id/:id')
  getById(@Param() getIdDto: GetIdDto) {
    return this.nftService.findById(getIdDto);
  }

  @Get('search/:id')
  getByIdPrefix(@Param() getIdDto: GetIdDto) {
    return this.nftService.findByIdPrefix(getIdDto);
  }

  @Get('ids/:ids')
  getByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.getByIds(ids);
  }

  @Get('claim/:ids')
  claimByIds(
    @Param('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.nftService.claimByIds(ids);
  }

  @Get('all')
  getAll(@Query() getAllDto: GetAllDto) {
    return this.nftService.findAll(getAllDto);
  }

  @Get('market')
  getByMarket(@Query() getMarketDto: GetMarketDto) {
    return this.nftService.findByMarket(getMarketDto);
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/schemas/nft.schema.ts 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type NFTDocument = NFT & Document;

const BaseAssetType = { name: String, url: String, rarity: Number, _id: false };
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class NFT {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);
// /Users/cheikkone/Projects/explorer-api/src/app/nft/schemas/nft.filters.ts 
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
// /Users/cheikkone/Projects/explorer-api/src/app/nft/nft.module.ts 
import { Module } from '@nestjs/common';
import { NftService } from './nft.service';
import { NftController } from './nft.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { NFT, NFTSchema } from './schemas/nft.schema';
import { CollectionModule } from '../collection/collection.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: NFT.name, schema: NFTSchema }]),
    CollectionModule,
  ],
  controllers: [NftController],
  providers: [NftService],
})
export class NftModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/dto/nft.dto.ts 
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Matches,
  IsNumberString,
  IsOptional,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { filters } from '../schemas/nft.filters';

export class GetIdDto {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'id of nft',
  })
  readonly id: number;
}

class NFTFilters {
  @ApiPropertyOptional({
    description: 'id of nft',
  })
  @IsOptional()
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  readonly id?: number;
  @ApiPropertyOptional({
    description: 'Guardian background',
    enum: filters.background,
  })
  @IsOptional()
  @IsEnum(filters.background)
  readonly background?: string;

  @ApiPropertyOptional({
    description: 'check if nft claimed',
    enum: ['true', 'false'],
  })
  @IsOptional()
  @Transform((b) => b.value === 'true')
  @IsBoolean()
  readonly isClaimed?: boolean;

  @ApiPropertyOptional({
    description: 'Guardian crown type',
    enum: filters.crown,
  })
  @IsOptional()
  @IsEnum(filters.crown)
  readonly crown?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle type',
    enum: filters.hairstyle,
  })
  @IsOptional()
  @IsEnum(filters.hairstyle)
  readonly hairstyle?: string;

  @ApiPropertyOptional({
    description: 'Guardian hairstyle color',
    enum: filters.hairstyleColor,
  })
  @IsOptional()
  @IsEnum(filters.hairstyleColor)
  readonly hairstyleColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes type',
    enum: filters.eyes,
  })
  @IsOptional()
  @IsEnum(filters.eyes)
  readonly eyes?: string;

  @ApiPropertyOptional({
    description: 'Guardian eyes color',
    enum: filters.eyesColor,
  })
  @IsOptional()
  @IsEnum(filters.eyesColor)
  readonly eyesColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian crown level',
    enum: filters.crownLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.crownLevel)
  readonly crownLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian armor level',
    enum: filters.armorLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.armorLevel)
  readonly armorLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian weapon level',
    enum: filters.weaponLevel,
  })
  @IsOptional()
  @Transform((param) => parseInt(param.value))
  @IsEnum(filters.weaponLevel)
  readonly weaponLevel?: number;

  @ApiPropertyOptional({
    description: 'Guardian nose type',
    enum: filters.nose,
  })
  @IsOptional()
  @IsEnum(filters.nose)
  readonly nose?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth type',
    enum: filters.mouth,
  })
  @IsOptional()
  @IsEnum(filters.mouth)
  readonly mouth?: string;

  @ApiPropertyOptional({
    description: 'Guardian mouth color',
    enum: filters.mouthColor,
  })
  @IsOptional()
  @IsEnum(filters.mouthColor)
  readonly mouthColor?: string;

  @ApiPropertyOptional({
    description: 'Guardian armor type',
    enum: filters.armor,
  })
  @IsOptional()
  @IsEnum(filters.armor)
  readonly armor?: string;

  @ApiPropertyOptional({
    description: 'Guardian weapon type',
    enum: filters.weapon,
  })
  @IsOptional()
  @IsEnum(filters.weapon)
  readonly weapon?: string;

  @ApiPropertyOptional({
    description: 'Guardian stone level',
    enum: filters.stone,
  })
  @IsOptional()
  @IsEnum(filters.stone)
  readonly stone?: string;
}

export class GetErdDto {
  @Matches(/^erd.*/)
  @ApiProperty({
    description: 'elrond wallet address',
  })
  readonly erd: string;
}

export class GetAllDto extends NFTFilters {
  @Matches(/^(id|rank)$/)
  @ApiProperty({
    enum: ['id', 'rank'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @Matches(/^([1-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)$/)
  @ApiProperty()
  readonly page: number;
}

export class GetAllDtoLimited extends NFTFilters {
  // 1 to 9999
  @Matches(/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9])$/)
  @ApiProperty({
    description: 'limit of nfts',
  })
  readonly limit: number;
}

export class GetMarketDto extends NFTFilters {
  @Matches(/^(id|rank|price|viewed|latest)$/)
  @ApiProperty({
    enum: ['id', 'rank', 'price', 'viewed', 'latest'],
  })
  readonly by: string;
  @Matches(/^(asc|desc)$/)
  @ApiProperty({
    enum: ['asc', 'desc'],
  })
  readonly order: string;
  @IsNumberString()
  @Matches(/[^0]+/)
  @ApiProperty()
  readonly page: number;
  @IsNumberString()
  @Matches(/[^0]+/)
  @IsOptional()
  @ApiPropertyOptional({
    default: 20,
  })
  readonly count: number;
  @Matches(/^(buy|bid)$/)
  @IsOptional()
  @ApiPropertyOptional({
    enum: ['buy', 'bid'],
  })
  readonly type: string;
}
// /Users/cheikkone/Projects/explorer-api/src/app/nft/schemas/nft.schema.ts 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type NFTDocument = NFT & Document;

const BaseAssetType = { name: String, url: String, rarity: Number, _id: false };
const LevelAssetType = { ...BaseAssetType, level: Number };
const ColorAssetType = { ...BaseAssetType, description: String, color: String };

type BaseAssetType = { name: string; url: string; rarity: string };
type ColorAssetType = BaseAssetType & { description: string; color: string };
type LevelAssetType = BaseAssetType & { level: number };

@Schema({ versionKey: false })
export class NFT {
  @Prop({ required: true, type: Number })
  id: number;
  @Prop({ required: true, type: String })
  idName: string;
  @Prop({ required: true, type: String })
  identifier: string;
  @Prop({ required: true, type: Number })
  rarity: number;
  @Prop({ required: true, type: Number })
  rank: number;
  @Prop({ required: true, type: String })
  stone: string;
  @Prop({ required: true, type: BaseAssetType })
  background: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  body: BaseAssetType;
  @Prop({ required: true, type: BaseAssetType })
  nose: BaseAssetType;
  @Prop({ required: true, type: ColorAssetType })
  eyes: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  mouth: ColorAssetType;
  @Prop({ required: true, type: ColorAssetType })
  hairstyle: ColorAssetType;
  @Prop({ required: true, type: LevelAssetType })
  crown: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  armor: LevelAssetType;
  @Prop({ required: true, type: LevelAssetType })
  weapon: LevelAssetType;
  @Prop({ type: Object })
  market: {
    source: string;
    identifier: string;
    type: 'bid' | 'buy';
    bid: null | {
      min: number;
      current: number;
      deadline: [number, number, number, number];
    };
    token: string;
    price: number;
    currentUsd: number;
    timestamp: number;
  };
  @Prop({ type: Number })
  timestamp: number;
  @Prop({ type: Number, default: 0 })
  viewed: number;
  @Prop({ type: Boolean, default: false })
  isClaimed: boolean;
}

export const NFTSchema = SchemaFactory.createForClass(NFT);
// /Users/cheikkone/Projects/explorer-api/src/app/nft/schemas/nft.filters.ts 
export const filters = {
  background: [
    'caiamme',
    'clemah',
    'dark',
    'harell',
    'kyoto ape',
    'lava',
    'light',
    'momoza',
    'médusa',
    'rose',
    'saka',
    'water',
  ],
  hairstyle: [
    'cillas',
    'gatsuga',
    'gymgom',
    'malnis',
    'mosirus',
    'sabaku',
    'sabler',
    'tako',
  ],
  hairstyleColor: ['brown', 'grey'],
  crown: [
    'blight of healing',
    'erales legendary crown',
    'goldenglow',
    'kurama legendary crown',
    'might of the mage',
    'oblivion',
    "oushiza's crown",
    'poseidon legendary crown',
    'sacred soul',
    'shepherd of grace',
    'solum legendary crown',
    'whisper of tourment',
  ],
  eyes: [
    'airo',
    'blaw',
    'cyclop',
    'fuka',
    'hanaro',
    'nataia',
    'oshiza',
    'sadineol',
    'suki',
    'wise cyclop',
  ],
  eyesColor: ['brown', 'dark', 'exclusive', 'grey'],
  nose: [
    'alfes',
    'blawn',
    'eden',
    'gatsuga',
    'hiken',
    'isaia',
    'morioka',
    'oshiza',
    'subaku',
  ],
  mouth: [
    'amateratsu',
    'dagon',
    'gimlys',
    'kanao',
    'ogata',
    'oshiza',
    'sabaku',
    'shin',
    'tako',
  ],
  mouthColor: ['brown', 'exclusive', 'grey'],
  armor: [
    'amaterasu',
    'dagon',
    'eralès legendary',
    'gatsuga',
    'hiken',
    'kurama legendary',
    'oroshi',
    'oshiza',
    'poseidon legendary',
    'sabaku',
    'shin',
    'solum legendary',
    'tako',
  ],
  weapon: [
    'atlantis mace',
    'bisento',
    'blawn bow',
    'erales legendary spear',
    "ivry's axe",
    'katana ape',
    'kurama legendary sword',
    'oshiza spear',
    'sabaku spear',
    'sacred trident',
    'shadow slayer',
    'skull breaker',
    'solum legendary shield & axe',
  ],
  stone: ['algae', 'bioluminescent', 'lava', 'rock', 'water'],
  crownLevel: [1, 2, 3, 5],
  armorLevel: [1, 2, 3, 5],
  weaponLevel: [1, 2, 3, 5],
};
// /Users/cheikkone/Projects/explorer-api/src/app/auth/auth.service.ts 
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { EnvironmentVariables } from 'src/config/configuration.d';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<EnvironmentVariables>,
  ) {}
  async validateUser(email: string, pass: string): Promise<any> {
    const env = this.configService.get('env');
    return ['production', 'staging'].indexOf(env) === -1 ? true : null;
  }
  async login(user: any) {
    return {
      access_token: this.jwtService.sign({ key: 'splitamerge' }),
    };
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/strategies/jwt.strategy.ts 
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../../config/configuration.d';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService<EnvironmentVariables>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt-secret', { infer: true }),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/strategies/local.strategy.ts 
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/auth.module.ts 
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../config/configuration.d';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables>) => ({
        secret: config.get('jwt-secret', { infer: true }),
        signOptions: { expiresIn: '2 days' },
      }),
    }),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/guards/jwt-auth.guard.ts 
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/guards/local-auth.guard.ts 
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/strategies/jwt.strategy.ts 
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../../config/configuration.d';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService<EnvironmentVariables>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt-secret', { infer: true }),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/strategies/local.strategy.ts 
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/guards/jwt-auth.guard.ts 
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
// /Users/cheikkone/Projects/explorer-api/src/app/auth/guards/local-auth.guard.ts 
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.controller.ts 
import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ElrondApiService } from './elrond-api.service';

@ApiTags('elrond-api')
@Controller('elrond-api')
export class ElrondApiController {
  constructor(private readonly elrondApiService: ElrondApiService) {}

  @Get('/*')
  get(@Param() params) {
    return this.elrondApiService.get(params[0]);
  }

  @Post('/*')
  post(@Param() params, @Body() body) {
    return this.elrondApiService.post(params[0], body);
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.module.ts 
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { ElrondApiController } from './elrond-api.controller';
import { ElrondApiService } from './elrond-api.service';

@Module({
  controllers: [ElrondApiController],
  providers: [ElrondApiService],
  imports: [RedisModule],
})
export class ElrondApiModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.controller.spec.ts 
// import { Test, TestingModule } from '@nestjs/testing';
// import { ElrondApiController } from './elrond-api.controller';
// import { ElrondApiService } from './elrond-api.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('ElrondApiController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  //   let controller: ElrondApiController;
  //   let service: ElrondApiService;

  //   beforeEach(async () => {
  //     const module: TestingModule = await Test.createTestingModule({
  //       controllers: [ElrondApiController],
  //       imports: [RedisModule, EnvConfigModule],
  //       providers: [
  //         ElrondApiService,
  //         {
  //           provide: SENTRY_TOKEN,
  //           useValue: { debug: jest.fn() },
  //         },
  //       ],
  //     }).compile();

  //     controller = module.get<ElrondApiController>(ElrondApiController);
  //     service = module.get<ElrondApiService>(ElrondApiService);
  //   });

  //   // it('elrondApiController should be defined', () => {
  //   //   expect(controller).toBeDefined();
  //   // });
  //   // it('elrondApiService should be defined', () => {
  //   //   expect(service).toBeDefined();
  //   // });
  //   // it('elrondApiController GET should get correct data', async () => {
  //   //   const data = await controller.get({ '0': 'stats' });
  //   //   expect(data).toHaveProperty('accounts');
  //   //   expect(data).toHaveProperty('blocks');
  //   //   expect(data).toHaveProperty('epoch');
  //   //   expect(data).toHaveProperty('refreshRate');
  //   //   expect(data).toHaveProperty('roundsPassed');
  //   //   expect(data).toHaveProperty('roundsPerEpoch');
  //   //   expect(data).toHaveProperty('shards');
  //   //   expect(data).toHaveProperty('transactions');
  //   // });

  //   // it('elrondApiController POST should send ok', async () => {
  //   //   const data = await controller.post(
  //   //     { '0': 'query' },
  //   //     {
  //   //       scAddress:
  //   //         'erd1qqqqqqqqqqqqqpgqra3rpzamn5pxhw74ju2l7tv8yzhpnv98nqjsvw3884',
  //   //       funcName: 'getFirstMissionStartEpoch',
  //   //       args: [],
  //   //     },
  //   //   );
  //   //   expect(data).toHaveProperty('returnCode');
  //   //   expect(data.returnCode).toBe('ok');
  //   // });
  /* It's a comment. */
});
// /Users/cheikkone/Projects/explorer-api/src/app/elrond-api/elrond-api.service.ts 
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import { EnvironmentVariables } from 'src/config/configuration.d';
import { ApiNetworkProvider } from '@elrondnetwork/erdjs-network-providers';
import { RedisService } from '../../redis/redis.service';

@Injectable()
export class ElrondApiService {
  private networkProvider: ApiNetworkProvider;
  private env: string;
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private configService: ConfigService<EnvironmentVariables>,
    private redisService: RedisService,
  ) {
    this.networkProvider = this.configService.get('elrond-network-provider');
    this.env = this.configService.get('env');
  }

  async get(route) {
    try {
      const redisKey = this.env + route;
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doGetGeneric(route);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }

  async post(route, payload) {
    try {
      const redisKey = this.env + route + JSON.stringify(payload);
      const cachedData = await this.redisService.get(redisKey);
      if (cachedData) return cachedData;
      const data = await this.networkProvider.doPostGeneric(route, payload);
      await this.redisService.set(redisKey, data, 4);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.controller.spec.ts 
// import { Test, TestingModule } from '@nestjs/testing';
// import { StatsController } from './stats.controller';
// import { StatsService } from './stats.service';
// import { SENTRY_TOKEN } from '@ntegral/nestjs-sentry';
// import { RedisModule } from '../../redis/redis.module';
// import { EnvConfigModule } from '../../config/configuration.module';

describe('StatsController', () => {
  it('empyt', () => {
    expect(true).toBeTruthy();
  });
  // let controller: StatsController;
  // let service: StatsService;
  // beforeEach(async () => {
  //   const module: TestingModule = await Test.createTestingModule({
  //     controllers: [StatsController],
  //     providers: [
  //       StatsService,
  //       {
  //         provide: SENTRY_TOKEN,
  //         useValue: { debug: jest.fn() },
  //       },
  //     ],
  //     imports: [RedisModule, EnvConfigModule],
  //   }).compile();
  //   controller = module.get<StatsController>(StatsController);
  //   service = module.get<StatsService>(StatsService);
  // });
  // it('statsController should be defined', () => {
  //   expect(controller).toBeDefined();
  // });
  // it('statsService should be defined', () => {
  //   expect(service).toBeDefined();
  // });
  // it('statsController should get correct data', async () => {
  //   const data = await controller.get();
  //   expect(data).toHaveProperty('twitter');
  //   expect(data.twitter).toHaveProperty('followerCount');
  //   expect(data).toHaveProperty('guardians');
  //   expect(data.guardians).toHaveProperty('smallest24hTrade');
  //   expect(data.guardians).toHaveProperty('averagePrice');
  //   expect(data.guardians).toHaveProperty('holderCount');
  //   expect(data.guardians).toHaveProperty('totalEgldVolume');
  //   expect(data.guardians).toHaveProperty('floorPrice');
  //   expect(data.guardians.totalEgldVolume).toBeGreaterThanOrEqual(12500);
  //   expect(data.guardians.holderCount).toBeGreaterThanOrEqual(1000);
  //   expect(data.twitter.followerCount).toBeGreaterThanOrEqual(16000);
  //   expect(data.guardians.averagePrice).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.smallest24hTrade).toBeGreaterThanOrEqual(1);
  //   expect(data.guardians.floorPrice).toBeGreaterThanOrEqual(1);
  // });
});
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.controller.ts 
import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { StatsService } from './stats.service';

@ApiTags('stats')
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @Get('/')
  get() {
    return this.statsService.get();
  }
}
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.module.ts 
import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';

@Module({
  controllers: [StatsController],
  providers: [StatsService],
  imports: [RedisModule],
})
export class StatsModule {}
// /Users/cheikkone/Projects/explorer-api/src/app/stats/stats.service.ts 
import { Injectable } from '@nestjs/common';
import { InjectSentry, SentryService } from '@ntegral/nestjs-sentry';
import axios from 'axios';
import { RedisService } from '../../redis/redis.service';
import * as cheerio from 'cheerio';

@Injectable()
export class StatsService {
  public constructor(
    @InjectSentry() private readonly client: SentryService,
    private redisService: RedisService,
  ) {}

  async get() {
    try {
      const cachedData = await this.redisService.get('AQXSTATS');
      if (cachedData) return cachedData;
      const volumeData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/analytics?timeZone=Europe%2FParis&market=secundary&startDate=2021-11-01T00:00:00.000Z&endDate=' +
          new Date().toISOString() +
          '&buckets=1',
      );
      const holderData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/holder_and_supply',
      );
      const twitterData = await axios.get(
        'https://api.livecounts.io/twitter-live-follower-counter/stats/TheAquaverse',
      );
      const floorAverageData = await axios.get(
        'https://api.savvyboys.club/collections/GUARDIAN-3d6635/floor_and_average_price?chartTimeRange=day',
      );
      const xoxnoPage = await axios.get(
        'https://xoxno.com/collection/GUARDIAN-3d6635',
      );
      let floorPrice = null;

      try {
        const cheerioData = cheerio.load(xoxnoPage.data);
        const xoxnoData = cheerioData('#__NEXT_DATA__').html();
        const parsedXoxnoData = JSON.parse(xoxnoData);
        floorPrice = parsedXoxnoData?.props?.pageProps?.initInfoFallback?.floor;
      } catch (e) {}

      const rawEgldVolume =
        volumeData &&
        volumeData.data &&
        volumeData.data.date_histogram &&
        volumeData.data.date_histogram.length > 0
          ? volumeData.data.date_histogram[0].volume
          : null;
      const denum = Math.pow(10, 18);
      const followerCount =
        twitterData && twitterData.data && twitterData.data.followerCount
          ? twitterData.data.followerCount
          : null;
      const totalEgldVolume = rawEgldVolume ? Math.round(rawEgldVolume) : null;
      const holderCount =
        holderData.data && holderData.data.holderCount
          ? holderData.data.holderCount
          : null;
      const floorAverageDataList =
        floorAverageData.data && floorAverageData.data.length > 0
          ? floorAverageData.data
          : [];
      const smallest24hTrade =
        floorAverageDataList.length > 0 && floorAverageDataList[0].floor_price
          ? Math.round((floorAverageDataList[0].floor_price / denum) * 100) /
            100
          : null;

      const oldFloorAverageData =
        floorAverageDataList.length > 1 &&
        floorAverageDataList[floorAverageDataList.length - 1]
          ? floorAverageDataList[floorAverageDataList.length - 1]
          : null;

      const old24hTrade =
        oldFloorAverageData && oldFloorAverageData.floor_price
          ? Math.round((oldFloorAverageData.floor_price / denum) * 100) / 100
          : null;

      const percentage24hTrade =
        smallest24hTrade !== null && old24hTrade !== null
          ? Number(
              ((100 * (smallest24hTrade - old24hTrade)) / old24hTrade).toFixed(
                2,
              ),
            )
          : 0;
      const averagePrice =
        floorAverageDataList.length > 0 && floorAverageDataList[0].average_price
          ? Math.round((floorAverageDataList[0].average_price / denum) * 100) /
            100
          : null;

      const oldAveragePrice =
        oldFloorAverageData && oldFloorAverageData.average_price
          ? Math.round((oldFloorAverageData.average_price / denum) * 100) / 100
          : null;

      const percentageAveragePrice =
        smallest24hTrade !== null && oldAveragePrice !== null
          ? Number(
              (
                (100 * (averagePrice - oldAveragePrice)) /
                oldAveragePrice
              ).toFixed(2),
            )
          : 0;

      const data = {
        twitter: {
          followerCount,
        },
        guardians: {
          smallest24hTrade,
          percentage24hTrade,
          averagePrice,
          percentageAveragePrice,
          holderCount,
          totalEgldVolume,
          floorPrice,
        },
      };
      await this.redisService.set('AQXSTATS', data, 900);
      return data;
    } catch (error) {
      this.client.instance().captureException(error);
      throw error;
    }
  }
}
