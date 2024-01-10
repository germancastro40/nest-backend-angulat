import { RegisterUserDto } from './dto/register-user.dto';
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from "bcryptjs";
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { Payload } from './interfaces/payload';
import { LoginResponse } from './interfaces/login-response';
import { create } from 'domain';


@Injectable()
export class AuthService {

  constructor(

    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService:JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {


      const {password, ...userData} = createUserDto

      const newUSer = new this.userModel({
        password: bcrypt.hashSync( password, 10),
        ...userData
      })
      await newUSer.save();

      const {password:_, ...user} = newUSer.toJSON()

      return user;


    } catch (error) {
      if( error.code === 11000){
        throw new BadRequestException(`el email:'${createUserDto.email.toUpperCase()}' ya se encuentra en uso`)
      }
      throw new InternalServerErrorException('Algo raro ocurrio, contacte a el administrador')
    }
    
  }

  findAll():Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById(id:string){
    const user = await this.userModel.findById( id )

    const {password, ...rest } = user.toJSON()

    return rest
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  async register(registerUserDto:RegisterUserDto):Promise<LoginResponse>{

   const newRegister = await this.create( registerUserDto )
   
   return {
      user: newRegister,
      token: this.getJwtToken({ id: newRegister._id})
   }
  }

  async login(loginDto: LoginDto):Promise<LoginResponse> {
    const {email, password} = loginDto

    const user = await this.userModel.findOne({ email })

    if( !user ){
      throw new UnauthorizedException('Credenciales no validas - email')
    }

    if ( !bcrypt.compareSync( password, user.password )){
      throw new UnauthorizedException('Credenciales no validas - password')
    }

    const {password:_, ...rest} = user.toJSON()

    return {
      ...rest,
      token: this.getJwtToken({ id: user.id }),
    }
  }

  getJwtToken(payload: Payload){
    const token = this.jwtService.sign(payload)

    return token;
  }
}
